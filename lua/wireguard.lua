local ffi = require "ffi"
local device = require "device"
local lm = require "libmoon"
local memory = require "memory"
local log = require "log"
local stats = require "stats"
local dpdk_export = require "missing-dpdk-stuff"

-- local msg = require "messages"
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
            
            local headroom, tailroom = dpdk_export.rte_pktmbuf_headroom_export(buf), dpdk_export.rte_pktmbuf_tailroom_export(buf)

            -- size checks
            if headroom < 16 then
                log:error("pktmbuf headroom of " .. headroom .. "to small for 16 byte header")
                lm.stop()
                return
            end

            if tailroom < 8 then
                log:error("pktmbuf tailroom of " .. tailroom .. "to small for " .. sodium.crypto_aead_chacha20poly1305_IETF_ABYTES .. " byte AEAD tag")
                lm.stop()
                return
            end

            -- save real IP packet sizes and pointer
            local pkt = buf:getBytes() + 14
            local len = buf:getSize() - 14

            -- extend mbuf
            if dpdk_export.rte_pktmbuf_append_export(buf, sodium.crypto_aead_chacha20poly1305_IETF_ABYTES) == nil then
                log:error("Could not extend tailroom")
                lm.stop()
                return
            end

            local err = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
                pkt, nil, -- cipertext (dst)
                pkt, len, -- plaintext (src)
                nil, 0,  -- addition data (unused)
                nil, -- nsec (unused)
                nonce, key
            )
            if err ~= 0 then
                log:error("Error encrypting packet")
                lm.stop()
                return
            end

            -- Counter check
            -- local cleartext = ffi.new("uint8_t[?]", len)
            -- err = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
            --     cleartext, nil, -- plaintext
            --     nil, -- nsec (unused)
            --     pkt, len + sodium.crypto_aead_chacha20poly1305_IETF_ABYTES, -- ciphertext
            --     nil, 0, -- addition data (unused)
            --     nonce, key
            -- )
            -- if err ~= 0 then
            --     log:error("decrypt failed")
            --     lm.stop()
            --     return
            -- end

            sodium.sodium_increment(nonce, sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)

            -- debug stats
            --headroom, tailroom = dpdk_export.rte_pktmbuf_headroom_export(buf), dpdk_export.rte_pktmbuf_tailroom_export(buf)
            --print(headroom, tailroom)
        end
        tunDevQueue:sendN(bufs, rx)
    end

end
