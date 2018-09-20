--- A simple UDP packet generator
local lm     = require "libmoon"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local memory = require "memory"
local arp    = require "proto.arp"
local server = require "webserver"
local ffi    = require "ffi"

-- set addresses here
local DST_MAC       = "3C:FD:FE:9E:D6:B8" -- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local SRC_IP        = "10.0.0.2" -- first address of /16 src subnet
local DST_IP        = "10.2.0.2" -- first address of /16 dst subnet
local SRC_PORT      = 1000
local DST_PORT      = 8000
local NUM_FLOWS     = 128

local jit = require "jit"
jit.opt.start("maxrecord=20000", "maxirconst=20000", "loopunroll=4000")

-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
        parser:description("Edit the source to modify constants like IPs and ports.")
        parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
        parser:option("-t --threads", "Number of threads per device."):args(1):convert(tonumber):default(1)
        parser:option("-r --rate", "Transmit rate in Mbit/s per device."):args(1)
        parser:option("-w --webserver", "Start a REST API on the given port."):convert(tonumber)
        parser:option("--pktLen", "Size of the send packets"):convert(tonumber):default(60)
        parser:option("-o --output", "File to output statistics to")
        parser:option("-s --seconds", "Stop after n seconds")
        parser:option("--vary", "How to generate flows. 'L2', 'L3'"):default("L3")
        parser:option("--flows", "Number of flow to generate. Must be power of two"):convert(tonumber):default(1024)
        parser:flag("--csv", "Output in CSV format")
        return parser:parse()
end

function master(args,...)
        log:info("Check out MoonGen (built on lm) if you are looking for a fully featured packet generator")
        log:info("https://github.com/emmericp/MoonGen")

        -- configure devices and queues
        for i, dev in ipairs(args.dev) do
                -- arp needs extra queues
                local dev = device.config{
                        port = dev,
                        txQueues = args.threads,
                        rxQueues = 1
                }
                args.dev[i] = dev
        end
        device.waitForLinks()


        if args.webserver then
                server.startWebserverTask{
                        port = args.webserver
                }
        end

        -- print statistics
        stats.startStatsTask{devices = args.dev, file = args.output, format = args.csv and "csv" or "plain"}

        -- configure tx rates and start transmit slaves
        for i, dev in ipairs(args.dev) do
                if i == 2 then
                        break
                end
                for i = 1, args.threads do
                        local queue = dev:getTxQueue(i - 1)
                        if args.rate then
                                queue:setRate(args.rate / args.threads)
                        end
                        lm.startTask("txSlave", queue, args)
                end
        end

        if args.seconds then
                lm.setRuntime(tonumber(args.seconds))
        end

        lm.waitForTasks()
end

function txSlave(queue, args)
        -- L2 source and destination in binary form for efficiency
        srcSubnet = ffi.new("union ip4_address"); srcSubnet:setString(SRC_IP)
        dstSubnet = ffi.new("union ip4_address"); dstSubnet:setString(DST_IP)

        local sqrtFlows = math.sqrt(args.flows) -- for src & dst modification

        local function varyL2(pkt)
                pkt.ip4.src:set(srcSubnet:get() + math.random(0, sqrtFlows - 1))
                pkt.ip4.dst:set(dstSubnet:get() + math.random(0, sqrtFlows - 1))
        end

        local function varyL3(pkt)
                pkt.udp:setSrcPort(SRC_PORT + math.random(0, sqrtFlows - 1))
                pkt.udp:setDstPort(DST_PORT + math.random(0, sqrtFlows - 1))
        end

        local modFn
        if args.vary == "L2" then
                modFn = varyL2
        elseif args.vary == "L2+L3" then
                modFn = function(pkt) varyL2(pkt); varyL3(pkt) end
        elseif args.vary == "L3" then
                modFn = varyL3
        else
                modFn = function() end
        end

        -- memory pool with default values for all packets, this is our archetype
        local mempool = memory.createMemPool(function(buf)
                buf:getUdpPacket():fill{
                        -- fields not explicitly set here are initialized to reasonable defaults
                        ethSrc = queue, -- MAC of the tx device
                        ethDst = DST_MAC,
                        ip4Src = SRC_IP,
                        ip4Dst = DST_IP,
                        udpSrc = SRC_PORT,
                        udpDst = DST_PORT,
                        pktLength = args.pktLen
                }
                buf:getUdpPacket().ip4:setFlags(2) -- Don't fragment
        end)
        -- a bufArray is just a list of buffers from a mempool that is processed as a single batch
        local bufs = mempool:bufArray()
        while lm.running() do -- check if Ctrl+c was pressed
                -- this actually allocates some buffers from the mempool the array is associated with
                -- this has to be repeated for each send because sending is asynchronous, we cannot reuse the old buffers here
                bufs:alloc(args.pktLen)
                for i, buf in ipairs(bufs) do
                        -- packet framework allows simple access to fields in complex protocol stacks
                        local pkt = buf:getUdpPacket()
                        modFn(pkt)
                end
                -- UDP checksums are optional, so using just IPv4 checksums would be sufficient here
                -- UDP checksum offloading is comparatively slow: NICs typically do not support calculating the pseudo-header checksum so this is done in SW
                bufs:offloadUdpChecksums()
                -- send out all packets and frees old bufs that have been sent
                queue:send(bufs)
        end
end
