local ffi = require "ffi"
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
        rssQueues = args.rxThreads
    }

    args.tunnel = device.config{
        port = args.tunnel,
        rxQueues = args.rxThreads,
        rssQueues = args.rxThreads,
        txQueues = args.workers
    }

    if sodium.sodium_init() < 0 then
        log:error("Setting up libsodium")
        lm.stop()
    end
    log:info("sodium init done")

    device.waitForLinks()

    stats.startStatsTask{devices = {args.gateway, args.tunnel}}

    local rings = {} -- create one SPSC ring for each worker
    for i=1, args.workers do
        table.insert(rings, pipe.newPacketRing(256))
        -- lm.startTask("worker", rings[i], args.tunnel:getTxQueue(i - 1))
        -- print("created worker", i, rings[i])
    end

    for i=1, args.workers do
        lm.startTask("worker", rings[i], args.tunnel:getTxQueue(i - 1))
        print("created worker", i, rings[i])
    end
    
    lm.startTask("slaveTaskRx", args.gateway:getRxQueue(0), rings)
    --lm.startTask("slaveTaskDecrypt", args.gateway:getTxQueue(0), args.tunnel:getRxQueue(0))
    
    lm.waitForTasks()
    log:info("[master]: Shutdown")
end

local function handshake()
    local txKey = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES)
    ffi.fill(txKey, sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES, 0xab)

    local rxKey = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES)
    ffi.fill(rxKey, sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES, 0xef)

    return txKey, rxKey
end

local function clearBufArray(bufs)
    for i = 1, bufs.size do
        bufs[i] = nil
    end
end

function worker(ring, txQueue)
    local id = txQueue.qid
    local counter = stats:newManualRxCounter("Worker " .. id)
    local info = function(...)
        print(string.format("[Worker %i]:", id), ...)
    end
    print(ring.ring, id)
    local srcPort, dstPort = 2000, 3000
    local outerSrcIP = ffi.new("union ip4_address"); outerSrcIP:setString("10.4.0.1")
    local outerDstIP = ffi.new("union ip4_address"); outerDstIP:setString("10.4.0.2")

    local key, _ = handshake()
    local nonce = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES, 0)
    
    bufs = memory.bufArray(4)

    while lm.running() do
        clearBufArray(bufs)
        local rx = ring:recv(bufs)
        
        -- for i = 1, rx do
        --     local buf = bufs[i]
        --     -- print(id, buf)
        --     counter:update(1, buf:getSize())
        --     txQueue:sendSingle(buf)
        -- end
        
        -- info("received from ring", rx, bufs.size)
        
        for i = 1, rx do
            local buf = bufs[i]
            counter:update(1, buf:getSize())
            
            if buf == nil then
                info("buf nil!", buf, i, rx)
            end
            
            local safe = dpdk_export.rte_pktmbuf_headroom_export(buf)
            local err = msg.encrypt(buf, key, nonce, 1)
            if err then
                log:error("Failed to encrypt:" .. err)
                print(safe)
                dpdk_export.rte_pktmbuf_reset_headroom_export(buf)
                print(dpdk_export.rte_pktmbuf_headroom_export(buf))
                lm.stop()
            end
            
            local pkt = buf:getUdp4Packet()
            pkt.eth:setType(eth.TYPE_IP)
            pkt.eth.dst:set(0x010203040506ull)
            pkt.eth.src:set(0x0a0b0c0d0e0full)
            
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
        end
        local tx = txQueue:sendN(bufs, rx)
        if not tx == 0 then
            print("tx", tx, "rx", rx)
        end
        -- bufs:freeAll()
    end
    counter:finalize()
end

function slaveTaskRx(gwDevQueue, rings)
    local fastIndexWrap = function(n, mod)
        if n <= mod then
            return n
        else
            return n - mod
        end
    end

    local nextRing = 1
    local numRings = #rings
    local bufs = memory.bufArray(64)

    -- require("jit.p").start("a")
    while lm.running() do
        clearBufArray(bufs)
        local rx = gwDevQueue:tryRecv(bufs, 1000 * 1000)
        
        for i = 1, rx do -- Debug
            if bufs[i] == nil then
                print("rxSlave",  "buf nil!", i)
            end
        end
        
        -- print("rxSlave", rx, nextRing, rings[1]:full(), rings[2]:full())
        if rx > 0 then

            -- local tx1 = rings[1]:sendN(bufs, rx)
            -- if tx1 == rx then
            --     goto next
            -- end
            -- local tx2 = rings[2]:sendN(bufs, rx)
            -- if tx2 == rx then
            --     goto next
            -- end
            -- print("rxSlave", "no ring free")
            -- bufs:freeAll()
            -- ::next::

            local suc = rings[nextRing]:sendN(bufs, rx)
            if suc ~= 0 and suc ~= rx then
                print(suc, rx)
                log:fatal("ring send fail: " .. tostring(suc) .. " is not 0 or " .. rx)
            end
            if suc == 0 then
                print("rxSlave", "ring full!", nextRing)
                bufs:freeAll()
            end

            -- nextRing = fastIndexWrap(nextRing + 1, numRings)
            nextRing = (nextRing % numRings) + 1
            -- nextRing = 1
        end
    end
    -- require("jit.p").stop()
end

function slaveTaskDecrypt(gwDevQueue, tunDevQueue)
    local srcPort, dstPort = 2000, 3000
    local outerDstIP = ffi.new("union ip4_address"):setString("10.0.0.1")
    local srcMac = gwDevQueue:getMacAddr()

    if sodium.sodium_init() < 0 then
        log:error("Setting up libsodium")
        lm.stop()
    end
    
    local key, _ = handshake()
    local nonce = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
    
    local bufs = memory.bufArray()

    -- Array holding bufs that should be forwarded
    local txBufs = memory.bufArray()

    local appendBuf = function(array, buf)
        array:resize(array.size + 1)
        array[array.size - 1] = buf
    end

    while lm.running() do
        local rx = tunDevQueue:tryRecv(bufs, 1000)
        txBufs:resize(0)
        for i = 1, rx do
            local buf = bufs[i]
            
            local err = msg.decrypt(buf, key, nonce)
            if err == nil then
                -- Emplace new ethernet header
                local ethpkt = buf:getEthPacket()
                ethpkt.eth:setType(eth.TYPE_IP)
                ethpkt.eth.dst:set(0x010203040506ull)
                ethpkt.eth.src:set(0x0a0b0c0d0e0full)
                appendBuf(txBufs, buf)
            else
                log:error(err)
                buf:free()
            end

            -- debug: decrypted packet
            -- buf:getUdp4Packet():dump(72)
        end
        gwDevQueue:sendN(txBufs, txBufs.size)
    end
end
