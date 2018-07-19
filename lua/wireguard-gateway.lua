local ffi = require "ffi"
local device = require "device"
local lm = require "libmoon"
local memory = require "memory"
local log = require "log"
local stats = require "stats"
local ip4 = require "proto.ip4"
local eth = require "proto.ethernet"
local dpdk_export = require "missing-dpdk-stuff"

local msg = require "messages"
local sodium = require "sodium"

local jit = require "jit"
jit.opt.start("maxrecord=20000", "maxirconst=20000", "loopunroll=4000")

function configure(parser)
    -- parser:argument("conf", "Path to wireguard configuration file")
    parser:argument("gateway", "Device to configure as gateway"):convert(tonumber)
    parser:argument("tunnel", "Device to use as tunnel"):convert(tonumber)
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
        rssQueues = args.rxThreads
    }

    -- device.waitForLinks()

    stats.startStatsTask{devices = {args.gateway, args.tunnel}}

    lm.startTask("slaveTaskEncrypt", args.gateway:getRxQueue(0), args.tunnel:getTxQueue(0))
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

function slaveTaskEncrypt(gwDevQueue, tunDevQueue)
    local srcPort, dstPort = 2000, 3000
    local outerSrcIP = ffi.new("union ip4_address"); outerSrcIP:setString("10.4.0.1")
    local outerDstIP = ffi.new("union ip4_address"); outerDstIP:setString("10.4.0.2")

    if sodium.sodium_init() < 0 then
        log:error("Setting up libsodium")
        lm.stop()
    end
    log:info("sodium init done")

    local key, _ = handshake()
    local nonce = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
    --sodium.randombytes_buf(nonce, sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
    ffi.fill(nonce + 8, 4, 0) -- lower 4 bytes are 0 since counter is only 8 bytes

    require("jit.p").start("fl")
    local bufs = memory.bufArray()
    while lm.running() do
        local rx = gwDevQueue:tryRecv(bufs, 1000)
        for i = 1, rx do
            local buf = bufs[i]

            -- debug: verbatim packet
            -- buf:getIP4Packet():dump(72)
            -- print("pre", buf.pkt_len, buf.data_len)

            local err = msg.encrypt(buf, key, nonce, outerSrcIP, outerDstIP, srcPort, dstPort, 1)
            if err then
                log:error("Failed to encrypt:" .. err)
                goto skip
            end

            sodium.sodium_increment(nonce, sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
            
            -- debug: transformed packet
            -- buf:getUdp4Packet():dump(72)
            -- print("post", buf.pkt_len, buf.data_len)
            -- headroom, tailroom = dpdk_export.rte_pktmbuf_headroom_export(buf), dpdk_export.rte_pktmbuf_tailroom_export(buf)
            -- print(headroom, tailroom)
            
            ::skip::
        end
        tunDevQueue:sendN(bufs, rx)
    end
    require("jit.p").stop()

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
