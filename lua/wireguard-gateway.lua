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

-- TODO: rename file to something with gateway or forward in name

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
    local txKey = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_ietf_keybytes())
    ffi.fill(txKey, sodium.crypto_aead_chacha20poly1305_ietf_keybytes(), 0xab)

    local rxKey = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_ietf_keybytes())
    ffi.fill(rxKey, sodium.crypto_aead_chacha20poly1305_ietf_keybytes(), 0xef)

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
    local nonce = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_ietf_npubbytes())
    print(nonce, sodium.crypto_aead_chacha20poly1305_ietf_npubbytes())

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

end

function slaveTaskDecrypt(gwDevQueue, tunDevQueue)
    local srcPort, dstPort = 2000, 3000
    local outerDstIP = ffi.new("union ip4_address"):setString("10.0.0.1")

    if sodium.sodium_init() < 0 then
        log:error("Setting up libsodium")
        lm.stop()
    end
    
    local key, _ = handshake()
    local nonce = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_ietf_npubbytes())
    
    local bufs = memory.bufArray()
    while lm.running() do
        local rx = tunDevQueue:tryRecv(bufs, 1000)
        for i = 1, rx do
            local buf = bufs[i]

            local ethPkt = buf:getEthPacket()
            if ethPkt.eth:getType() ~= eth.TYPE_IP then
                log:error("Received unsupported L3 type: " .. ethPkt.eth:getTypeString())
                goto skip
            end

            local ipPacket = buf:getIP4Packet()
            if ipPacket.ip4:getProtocol() ~= ip4.PROTO_UDP then
                log:error("Received non UDP packet: " .. ipPacket.ip4:getProtocolString())
                goto skip
            end

            -- We don't actually know yet if it's really a data frame, but the header is uniform across all types
            local message_data = ffi.cast("struct message_data*", buf:getBytes() + 14 + 20 + 8)
            if message_data.header.type ~= ffi.C.MESSAGE_DATA then
                log:error("Received unknown wireguard frame: " .. message_data.header.type)
                goto skip
            end

            if message_data.key_idx ~= 1 then
                log:error("Unknown key index: " .. message_data.key_idx)
                goto skip
            end

            ffi.cast("uint64_t*", nonce)[0] = message_data.counter

            local payload = buf:getBytes() + 14 + 20 + 8 + 16
            local innerL3Len = buf:getSize() - 20 - 8 - 16
            local err = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
                payload, nil, -- plaintext
                nil, -- nsec (unused)
                payload, innerL3Len + sodium.crypto_aead_chacha20poly1305_IETF_ABYTES, -- ciphertext
                nil, 0, -- addition data (unused)
                nonce, key
            )
            if err ~= 0 then
                log:error("Could not decrypt packet")
                goto skip
            end

            -- Move ethernet header
            ffi.copy(buf:getBytes() + 20 + 8 + 16, buf:getBytes(), 14)

            -- Truncate mbuf
            if rte_pktmbuf_trim_export(buf, sodium.crypto_aead_chacha20poly1305_IETF_ABYTES) ~= 0 then
                log:error("error trimming tailroom")
                lm.stop()
                return
            end

            if rte_pktmbuf_adj_export(buf, 20 + 16 + 8) == nil then
                log:error("error trimming headroom")
                lm.stop()
                return
            end

            -- debug: decrypted packet
            -- buf:getUdp4Packet():dump(72)
            
            ::skip::
        end
        gwDevQueue:sendN(bufs, rx)
    end
end
