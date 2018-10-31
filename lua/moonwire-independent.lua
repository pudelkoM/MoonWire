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
local peerLib = require "peer"

local jit = require "jit"
jit.opt.start("maxrecord=20000", "maxirconst=20000", "loopunroll=4000")

DSTMAC = "68:05:CA:32:44:98"

function configure(parser)
    -- parser:argument("conf", "Path to wireguard configuration file")
    parser:argument("gateway", "Device to configure as gateway"):convert(tonumber)
    parser:argument("tunnel", "Device to use as tunnel"):convert(tonumber)
    parser:option("--threads", "Number of threads"):convert(tonumber):default(1)
    parser:option("--lock", "Type of lock to use"):default("rte")
    local args = parser:parse()
    return args
end

function master(args)
    args.gateway = device.config{
        port = args.gateway,
        numBufs = args.threads * 2047,
        rxQueues = args.threads,
        rssQueues = args.threads
    }

    args.tunnel = device.config{
        port = args.tunnel,
        rxQueues = 1,
        rssQueues = 1,
        txQueues = args.threads
    }

    device.waitForLinks()

    stats.startStatsTask{devices = {args.gateway, args.tunnel}}

    -- local peer = peerLib.newPeer("pthreads")
    local peer = peerLib.newPeer(args.lock)
    log:info("sizeof(peer): " .. ffi.sizeof(peer))

    -- maybe use dpdk.startTaskOnCore
    for i=1, args.threads do
        lm.startTask("slaveTaskEncrypt", args.gateway:getRxQueue(i - 1), args.tunnel:getTxQueue(i - 1), peer)
        print("created thread", i, peer)
    end

    lm.waitForTasks()
    log:info("[master]: Shutdown")
end

function slaveTaskEncrypt(gwDevQueue, tunDevQueue, peer)
    local id = gwDevQueue.qid
    local counter = stats:newManualRxCounter("Worker " .. id)
    local dstMac = ffi.new("union mac_address"); dstMac:setString(DSTMAC)
    local srcMac = tunDevQueue.dev:getMac()
    local outerSrcIP = ffi.new("union ip4_address"); outerSrcIP:setString("10.1.0.1")
    local srcPort = 2000

    if sodium.sodium_init() < 0 then
        log:error("Setting up libsodium")
        lm.stop()
    end
    log:info("sodium init done")
    sodium.log_CPU_features()

    require("jit.p").start("a")
    local bufs = memory.bufArray(63)
    while lm.running() do
        local rx = gwDevQueue:tryRecv(bufs, 1000)
        peer:lock()
        for i = 1, rx do
            local buf = bufs[i]
            counter:update(1, buf:getSize())

            -- debug: verbatim packet
            -- buf:getIP4Packet():dump(72)
            -- print("pre", buf.pkt_len, buf.data_len)

            local err = msg.encrypt(buf, peer.txKey, peer.nonce, peer.id)
            if err then
                log:error("Failed to encrypt:" .. err)
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
        peer:unlock()
        tunDevQueue:sendN(bufs, rx)
    end
    require("jit.p").stop()
    log:info("[Worker " .. id .. "]: Shutdown")
end
