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
    args.rxThreads = 1

    args.gateway = device.config{
        port = args.gateway,
        rxQueues = args.rxThreads,
        -- rssQueues = args.rxThreads
        -- numBufs = args.workers * 2047,
        numBufs = 12 * 2047,
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
        -- lm.startTask("worker", rings[i], args.tunnel:getTxQueue(i - 1))
        -- print("created worker", i, rings[i])
    end
    
    for i=1, args.workers do
        lm.startTask("worker", rings[i], args.tunnel:getTxQueue(i - 1))
        print("[master]: created worker", i, rings[i])
    end
    
    lm.startTask("slaveTaskRx", args.gateway:getRxQueue(0), rings)
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
    local outerDstIP = ffi.new("union ip4_address"); outerDstIP:setString("10.2.0.2")
    local srcPort, dstPort = 2000, 3000

    bufs = memory.bufArray(2^5 - 1)

    -- require("jit.p").start("a2")
    while lm.running() do
        local rx = ring:recv(bufs)

        for i = 1, rx do
            local buf = bufs[i]
            counter:update(1, buf:getSize())

            local args_buf = ffi.cast("struct rte_mbuf*", buf.udata64)
            if args_buf == nil or buf == nil then
                log:error("null ptr " .. tostring(args_buf) .. " buf " .. tostring(args_buf))
                lm.stop()
            end
            local peer = ffi.cast("struct peer_rte_spinlock*", args_buf:getData())

            -- debug: verbatim packet
            -- buf:getIP4Packet():dump(72)
            -- print("pre", buf.pkt_len, buf.data_len)

            local err = msg.encrypt(buf, peer.txKey, peer.nonce, peer.id)
            args_buf:free()
            if err then
                log:error("Failed to encrypt:" .. err)
                lm.stop()
                goto skip
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
            pkt.ip4.dst.uint32 = outerDstIP.uint32

            pkt.udp:fill{
                udpSrc = srcPort,
                udpDst = dstPort,
                udpLength = buf:getSize() - 14 - 20,
                udpChecksum = 0x0 -- disable checksumming since we have crypto authentication
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
end

ffi.cdef[[
    unsigned int rte_mempool_avail_count(const struct rte_mempool *mp);
    struct rte_mbuf* alloc_mbuf(struct mempool* mp);
    void alloc_mbufs(struct mempool* mp, struct rte_mbuf* bufs[], uint32_t len, uint16_t pkt_len);
]]

local function stub_alloc(pool, l)
    local m = C.alloc_mbuf(pool)
    if m ~= nil then
        m.pkt_len = l
        m.data_len = l
    end
    return m
end

function slaveTaskRx(gwDevQueue, rings)
    local fastIndexWrap = function(n, mod)
        if n <= mod then
            return n
        else
            return n - mod
        end
    end

    -- lm.sleepMillis(1000 * 2)

    local peer = peerLib.newPeer("rte")
    local peer_size = ffi.sizeof(peer)
    local peer_nonce = peer.nonce
    local mempool_work = memory.createMemPool({n = 2^18 - 1, bufSize = peer_size})

    local nextRing = 1
    local numRings = #rings
    local batchSize = 255
    local bufs = memory.bufArray(batchSize)
    local work_bufs = mempool_work:bufArray(batchSize)

    require("jit.p").start("a")
    while lm.running() do
        local rx = gwDevQueue:tryRecv(bufs, 1000 * 1000)    
    
        -- print("rxSlave", rx, nextRing, rings[1]:full(), rings[2]:full())
        -- print("rxSlave", rx, nextRing, rings[1]:full(), ffi.C.rte_mempool_avail_count(ffi.cast("struct rte_mempool*", mempool_work)))
        if rx > 0 then
            -- attach crypto args
            work_bufs:allocN(ffi.sizeof(peer), rx)
            for i = 1, rx do
                local buf = bufs[i]
                local args_buf = work_bufs[i]
                -- local args_buf = stub_alloc(mempool_work, ffi.sizeof(peer))
                if args_buf == nil or buf == nil then
                    log:error("oom, increase mempool size");
                    lm.stop()
                end
                buf.udata64 = ffi.cast("uint64_t", args_buf)
                ffi.copy(args_buf:getBytes(), peer, ffi.sizeof(peer))
                sodium.sodium_increment(peer_nonce, sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
                -- -- print(args_buf:dump(ffi.sizeof(peer)))
            end

            local suc = rings[nextRing]:sendN(bufs, rx)
            -- print("rxSlave", suc)

            if not suc then
                -- print("rxSlave", "ring full!", nextRing)
                for i = 1, rx do
                    local buf = bufs[i]
                    local args_buf = ffi.cast("struct rte_mbuf*", buf.udata64)
                    if buf == nil or args_buf == nil then
                        log:error("null ptr " .. tostring(buf) .. " buf " .. tostring(args_buf))
                        lm.stop()
                    end
                    args_buf:free()
                end
                bufs:free(rx)
                work_bufs:free(rx)
            end
            
            nextRing = fastIndexWrap(nextRing + 1, numRings)
        end
    end
    require("jit.p").stop()
end
