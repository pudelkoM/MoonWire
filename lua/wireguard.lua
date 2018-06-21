local ffi = require "ffi"
local device = require "device"
local lm = require "libmoon"
local memory = require "memory"
local log = require "log"
local stats = require "stats"

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
    
    device.waitForLinks()

    stats.startStatsTask{devices = args.dev}

    lm.startTask("slaveTaskEncrypt", args.gateway:getRxQueue(0), args.tunnel:getTxQueue(0))

    lm.waitForTasks()
    log:info("[master]: Shutdown")
end

local function handshake()

end

function slaveTaskEncrypt(gwDevQueue, tunDevQueue)
    if sodium.sodium_init() < 0 then
        log:error("Setting up libsodium")
        lm.stop()
    end

    local bufs = memory.bufArray()
	while lm.running() do
		local rx = gwDevQueue:tryRecv(bufs, 1000)
		for i = 1, rx do
            local pkt = bufs[i]:getEthernetPacket()
            print(pkt)
            
			-- -- swap MAC addresses
			-- local pkt = bufs[i]:getEthernetPacket()
			-- local tmp = pkt.eth:getDst()
			-- pkt.eth:setDst(pkt.eth:getSrc())
            -- pkt.eth:setSrc(tmp)
            

		end
		tunDevQueue:sendN(bufs, rx)
	end

end
