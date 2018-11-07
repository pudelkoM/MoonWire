local ffi = require "ffi"
local C = ffi.C
local device = require "device"
local lm = require "libmoon"
local memory = require "memory"
local log = require "log"
local stats = require "stats"
local ip4 = require "proto.ip4"
local eth = require "proto.ethernet"
local pipe = require "pipe"
local dpdk_export = require "missing-dpdk-stuff"

local msg = require "messages"
local sodium = require "sodium"
local peerLib = require "peer"
local mempool = require "mempool"

DSTMAC = "68:05:CA:32:44:98"

local jit = require "jit"
jit.opt.start("maxrecord=20000", "maxirconst=20000", "loopunroll=4000")

function configure(parser)
    -- parser:argument("conf", "Path to wireguard configuration file")
    parser:argument("gateway", "Device to configure as gateway"):convert(tonumber)
    parser:argument("tunnel", "Device to use as tunnel"):convert(tonumber)
    parser:option("--workers", "Number of encryption workers."):args(1):convert(tonumber):default(1)
    local args = parser:parse()
    return args
end

function master(args)
    args.gateway = device.config{
        port = args.gateway,
        rxQueues = 1,
        rssQueues = 1,
        numBufs = math.min(args.workers * 2^12 - 1, 2^15),
        txQueues = 1,
    }

    args.tunnel = device.config{
        port = args.tunnel,
        rxQueues = 1,
        txQueues = args.workers,
        -- rssQueues = args.rxThreads,
    }

    if sodium.sodium_init() < 0 then
        log:error("Setting up libsodium")
        lm.stop()
    end
    log:info("sodium init done")
    sodium.log_CPU_features()

    device.waitForLinks()

    stats.startStatsTask{devices = {args.gateway, args.tunnel}}

    local rings = {} -- create one SPSC ring for each worker
    for i=1, args.workers do
        table.insert(rings, pipe.newPacketRing(2^10 - 1))
        lm.startTask("worker", rings[i], args.tunnel:getTxQueue(i - 1))
        print("[master]: created worker", i, rings[i])
    end
    
    local rxToCopyRing = pipe.newPacketRing(2^8 - 1)
    lm.startTask("copyTask", rxToCopyRing, rings)
    print("[master]: created copyTask")
    lm.startTask("slaveTaskRx", args.gateway:getRxQueue(0), rxToCopyRing)
    print("[master]: created slaveTaskRx")
    
    lm.waitForTasks()
    log:info("[master]: Shutdown")
end

function worker(ring, txQueue)
    local id = txQueue.qid
    local counter = stats:newManualRxCounter("Worker " .. id)
    local info = function(...)
        print(string.format("[Worker %i]:", id), ...)
    end
    print(ring.ring, id)
    local dstMac = ffi.new("union mac_address"); dstMac:setString(DSTMAC)
    local srcMac = txQueue.dev:getMac()
    local outerSrcIP = ffi.new("union ip4_address"); outerSrcIP:setString("10.1.0.1")
    local srcPort = 2000

    bufs = memory.bufArray(2^5 - 1)

    -- require("jit.p").start("a")
    while lm.running() do
        local rx = ring:recv(bufs)

        for i = 1, rx do
            local buf = bufs[i]
            counter:update(1, buf:getSize())

            -- debug: verbatim packet
            -- buf:getIP4Packet():dump(72)
            -- print("pre", buf.pkt_len, buf.data_len)
            
            local args_buf = ffi.cast("struct work*", buf.udata64)
            local peer = args_buf.peer
            local err = msg.encrypt(buf, peer.txKey, peer.nonce, peer.id)
            dpdk_export.rte_mempool_put_export(args_buf.pool, args_buf)
            if err then
                log:error("Failed to encrypt:" .. err)
                lm.stop()
            end

            -- Create outer headers
            local pkt = buf:getUdp4Packet()
            pkt.eth:setType(eth.TYPE_IP)
            pkt.eth.dst = dstMac
            pkt.eth.src = srcMac

            pkt.ip4:setVersion()
            pkt.ip4:setHeaderLength()
            pkt.ip4:setTOS()
            pkt.ip4:setLength(buf:getSize() - 14)
            pkt.ip4:setID()
            pkt.ip4:setFlags()
            pkt.ip4:setFragment()
            pkt.ip4:setTTL()
            pkt.ip4:setProtocol(ip4.PROTO_UDP)
            pkt.ip4:setChecksum()
            pkt.ip4.src.uint32 = outerSrcIP.uint32
            pkt.ip4.dst.uint32 = peer.endpoint.uint32

            pkt.udp:fill{
                udpSrc = srcPort,
                udpDst = peer.endpoint_port,
                udpLength = buf:getSize() - 14 - 20,
                udpChecksum = 0x0 -- disable checksumming since we have crypto integrety protection
            }
            
            -- debug: transformed packet
            -- buf:getUdp4Packet():dump(72)
            -- print("post", buf.pkt_len, buf.data_len)
            -- headroom, tailroom = dpdk_export.rte_pktmbuf_headroom_export(buf), dpdk_export.rte_pktmbuf_tailroom_export(buf)
            -- print(headroom, tailroom)
            
            ::skip::
        end
        txQueue:sendN(bufs, rx)
    end
    require("jit.p").stop()
    counter:finalize()
    log:info("[Worker " .. id .. "]: Shutdown")
end

ffi.cdef[[
    struct work {
        struct peer_no_lock peer __attribute__((aligned(64)));
        struct rte_mempool* pool;
    };
]]

function slaveTaskRx(gwDevQueue, outputRing)
    local batchSize = 31
    local bufs = memory.bufArray(batchSize)
    -- require("jit.p").start("a")
    while lm.running() do
        local rx = gwDevQueue:tryRecv(bufs, 1000)
        if rx > 0 then
            local suc = outputRing:sendN(bufs, rx)
            if not suc then
                bufs:free(rx)
            end
        end
    end
    require("jit.p").stop()
    log:info("[rxSlave]: Shutdown")
end


function copyTask(inputRing, rings)
    local fastIndexWrap = function(n, mod)
        if n <= mod then
            return n
        else
            return n - mod
        end
    end

    local peer = peerLib.newPeer("no_lock")
    log:info("sizeof(peer): " .. ffi.sizeof(peer))
    local peer_size = ffi.sizeof(peer)
    local peer_nonce = peer.nonce

    local mp = mempool.createMempool(
        2^18-1, ffi.sizeof("struct work"), select(2, lm.getCore()), 
        function(work, pool)
            local work = ffi.cast("struct work*", work)
            work.pool = pool
            work.peer = peer
        end,
        bit.bor(mempool.MEMPOOL_F_SC_GET, mempool.MEMPOOL_F_NO_PHYS_CONTIG)
    )
    
    local nextRing = 1
    local numRings = #rings
    local batchSize = 127
    local bufs = memory.bufArray(batchSize)
    local work_bufs = mp:bufArray(batchSize)

    -- require("jit.p").start("a")
    while lm.running() do
        local rx = inputRing:recv(bufs)

        if rx > 0 then
            -- create & attach crypto args
            work_bufs:allocN(rx)
            for i = 1, rx do
                local buf = bufs[i]
                local args_buf = ffi.cast("struct work*", work_bufs[i])
                if buf == nil or args_buf == nil then
                    log:error("oom, increase mempool size");
                    lm.stop()
                end
                buf.udata64 = ffi.cast("uint64_t", args_buf)
                args_buf.peer = peer
                -- ffi.copy(args_buf.peer, peer, ffi.sizeof(peer))
                sodium.sodium_increment(peer_nonce, sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
            end

            for tries = 1, 999999 do
                local suc = rings[nextRing]:sendN(bufs, rx)
                if suc then
                    goto done
                else
                    nextRing = fastIndexWrap(nextRing + 1, numRings)
                end
            end
            bufs:free(rx)
            work_bufs:free(rx)
            ::done::

            -- local suc = rings[nextRing]:sendN(bufs, rx)
            -- if not suc then
            --     bufs:free(rx)
            --     work_bufs:free(rx)
            -- end
            -- nextRing = fastIndexWrap(nextRing + 1, numRings)
        end
    end
    require("jit.p").stop()
    log:info("[copyTask]: Shutdown")
end
