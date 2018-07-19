local ffi = require "ffi"
local device = require "device"
local lm = require "libmoon"
local memory = require "memory"
local log = require "log"
local stats = require "stats"
local ip4 = require "proto.ip4"
local eth = require "proto.ethernet"

package.path = package.path .. ";./lua/?.lua"

local msg = require "messages"
local sodium = require "sodium"

local jit = require "jit"
jit.opt.start("maxrecord=20000", "maxirconst=20000", "loopunroll=4000")

local DST_MAC = "68:05:ca:32:44:d8" -- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local SRC_IP = "10.0.0.1"
local DST_IP = "10.0.2.2"
local SRC_PORT_BASE = 1234 -- actual port will be SRC_PORT_BASE * random(NUM_FLOWS)
local DST_PORT = 1234
local NUM_FLOWS = 1000

function configure(parser)
    parser:argument("txdev", "Device to send plaintext packets to"):convert(tonumber)
    parser:argument("rxdev", "Device from expect encrypted packets back"):convert(tonumber)
    parser:option("--txThreads", "Number of Tx threads."):args(1):convert(tonumber):default(1)
    parser:option("--rxThreads", "Number of Rx threads."):args(1):convert(tonumber):default(1)
    parser:option("-r --rate", "Transmit rate in Mbit/s."):args(1)
    parser:option("--size", "Size of the send packets"):convert(tonumber):default(60)
    return parser:parse()
end

function master(args)
    args.txdev = device.config{
        port = args.txdev,
        txQueues = args.txThreads,
    }

    args.rxdev = device.config{
        port = args.rxdev,
        rxQueues = args.rxThreads,
        rssQueues = args.rxThreads
    }

    -- device.waitForLinks()

    stats.startStatsTask{devices = {args.txdev, args.rxdev}}

    for i = 1, args.txThreads do
        local queue = args.txdev:getTxQueue(i - 1)
        if args.rate then
                queue:setRate(args.rate / args.txThreads)
        end
        lm.startTask("txSlave", queue, DST_MAC, args.size)
    end

    for i = 1, args.rxThreads do
        lm.startTask("slaveTaskDecrypt", args.rxdev:getRxQueue(i - 1))
    end

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

function txSlave(queue, dstMac, pktLen)
    local mempool = memory.createMemPool(function(buf)
            buf:getUdpPacket():fill{
                    ethSrc = queue, -- MAC of the tx device
                    ethDst = dstMac,
                    ip4Src = SRC_IP,
                    ip4Dst = DST_IP,
                    udpSrc = SRC_PORT,
                    udpDst = DST_PORT,
                    pktLength = pktLen
            }
            buf:getUdpPacket().ip4:setFlags(2) -- Don't fragment
            local payload = buf:getBytes() + 14 + 20 + 8
            payload[0] = 0xab
            payload[1] = 0xcd
    end)
    local bufs = mempool:bufArray()
    while lm.running() do -- check if Ctrl+c was pressed
            bufs:alloc(pktLen)
            for i, buf in ipairs(bufs) do
                    local pkt = buf:getUdpPacket()
                    pkt.udp:setSrcPort(SRC_PORT_BASE + math.random(0, NUM_FLOWS - 1))
            end
            bufs:offloadUdpChecksums()
            queue:send(bufs)
    end
end

function slaveTaskDecrypt(queue)
    local srcPort, dstPort = 2000, 3000
    local outerDstIP = ffi.new("union ip4_address"); outerDstIP:setString("10.0.0.1")

    if sodium.sodium_init() < 0 then
        log:error("Setting up libsodium")
        lm.stop()
    end
    
    local key, _ = handshake()
    local nonce = ffi.new("uint8_t[?]", sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
    
    local bufs = memory.bufArray()
    while lm.running() do
        local rx = queue:tryRecv(bufs, 1000)
        for i = 1, rx do
            local buf = bufs[i]
            local err = msg.decrypt(buf, key, nonce)
            if err ~= nil then
                log:error(err)
                lm.stop()
                buf:getUdp4Packet():dump(buf:getSize())
                print(msg._getWgDataPacket(buf))
                return
            end

            -- debug: decrypted packet
            -- buf:dump(buf:getSize())
        end
        bufs:freeAll()
    end
end
