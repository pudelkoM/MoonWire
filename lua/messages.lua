local ffi = require "ffi"
local bor, band, bnot, rshift, lshift = bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift

local dpdk_export = require "missing-dpdk-stuff"
local sodium = require "sodium"

local eth = require "proto.ethernet"
local ip4 = require "proto.ip4"


local wg = {}

wg.MESSAGE_INVALID = 0
wg.MESSAGE_HANDSHAKE_INITIATION = 1
wg.MESSAGE_HANDSHAKE_RESPONSE = 2
wg.MESSAGE_HANDSHAKE_COOKIE = 3
wg.MESSAGE_DATA = 4

ffi.cdef[[
    enum message_type {
        MESSAGE_INVALID = 0,
        MESSAGE_HANDSHAKE_INITIATION = 1,
        MESSAGE_HANDSHAKE_RESPONSE = 2,
        MESSAGE_HANDSHAKE_COOKIE = 3,
        MESSAGE_DATA = 4
    };

    struct message_header {
        /* The actual layout of this that we want is:
            * u8 type
            * u8 reserved_zero[3]
            *
            * But it turns out that by encoding this as little endian,
            * we achieve the same thing, and it makes checking faster.
            */
        uint32_t type;
    };

    struct message_data {
        struct message_header header;
        uint32_t key_idx;
        uint64_t counter;
        uint8_t encrypted_data[];
    };
]]

local message_header = {}
function message_header:__tostring()
    local t = band(self.type, 0xff)
    local r0, r1, r2 = 0, 0, 0
    return string.format("{type: %u, reserved: [%u, %u, %u], raw: %u}", t, r0, r1, r2, self.type)
end
message_header.__index = message_header
ffi.metatype("struct message_header", message_header)

local message_data = {}

function message_data:__tostring()
    return ("struct message_data {header: %s, key_idx: %u, counter: %s}"):format(self.header, self.key_idx, tostring(self.counter))
end

message_data.__index = message_data
ffi.metatype("struct message_data", message_data)

-- Does not validate the packet
function wg._getWgDataPacket(buf, offset)
    offset = offset or 14 + 20 + 8
    return ffi.cast("struct message_data*", buf:getBytes() + offset)
end

-- Returns wireguard packet
function wg.getWgDataPacket(buf)
    local offset = 14 -- Ethernet header

    -- Check for IPv4
    local ethPkt = buf:getEthPacket()
    if ethPkt.eth:getType() ~= eth.TYPE_IP then
        return nil, "Unsupported L3 type: " .. ethPkt.eth:getTypeString()
    end

    local ipPacket = buf:getIP4Packet()
    if ipPacket.ip4:getProtocol() ~= ip4.PROTO_UDP then
        return nil, "Non UDP packet: " .. ipPacket.ip4:getProtocolString()
    end
    offset = offset + ipPacket.ip4:getHeaderLength() * 4
    offset = offset + 8 -- UDP header

    -- We don't actually know yet if it's really a data frame, but the header is uniform across all types
    local message_data = ffi.cast("struct message_data*", buf:getBytes() + offset)
    if message_data.header.type ~= wg.MESSAGE_DATA then
        return nil, "Received unknown wireguard frame: " .. message_data.header.type
    end

    return message_data
end

function wg.encrypt(buf, key, nonce, tunnelSrc, tunnelDst, srcPort, dstPort, key_idx)
    -- mbuf layout transformation is as follows:
    -- from:
    -- | ethernet header | inner L3 packet |
    -- to:
    -- | new ethernet header | outer IP header | outer UDP header | WG data message header | encrypted L3 packet |

    -- save inner L3 packet size
    local innerL3Len = buf:getSize() - 14
    
    -- extend mbuf tailroom for AEAD auth tag
    if dpdk_export.rte_pktmbuf_append_export(buf, sodium.crypto_aead_chacha20poly1305_IETF_ABYTES) == nil then
        return "Could not extend tailroom"
    end

    -- extend headroom for WG data messsage header
    local inc_headroom = ffi.sizeof("struct message_data") + 20 + 8 -- new IPv4 & UDP header
    if dpdk_export.rte_pktmbuf_prepend_export(buf, inc_headroom) == nil then
        return "Could not extend headroom"
    end

    -- Create outer headers
    -- TODO: Use correct Src & Dst MACs
    local pkt = buf:getUdp4Packet()
    pkt.eth:setType(eth.TYPE_IP)
    pkt.eth.dst:set(0x010203040506ull)
    pkt.eth.src:set(0x0a0b0c0d0e0full)

    pkt.ip4:setVersion()
    pkt.ip4:setHeaderLength()
    pkt.ip4:setTOS()
    pkt.ip4:setLength(innerL3Len + inc_headroom + sodium.crypto_aead_chacha20poly1305_IETF_ABYTES)
    pkt.ip4:setID()
    pkt.ip4:setFlags()
    pkt.ip4:setFragment()
    pkt.ip4:setTTL()
    pkt.ip4:setProtocol(ip4.PROTO_UDP)
    pkt.ip4:setChecksum()
    pkt.ip4.src.uint32 = tunnelSrc.uint32
    pkt.ip4.dst.uint32 = tunnelDst.uint32

    pkt.udp:fill{
        udpSrc = srcPort,
        udpDst = dstPort,
        udpLength = innerL3Len + ffi.sizeof("struct message_data") + sodium.crypto_aead_chacha20poly1305_IETF_ABYTES,
        udpChecksum = 0x0 -- disable checksumming since we have crypto authentication
    }

    -- create WG data message header
    local msgData = ffi.cast("struct message_data*", buf:getBytes() + 14 + 20 + 8)
    msgData.header.type = wg.MESSAGE_DATA
    msgData.key_idx = key_idx
    msgData.counter = ffi.cast("uint64_t*", nonce)[0] -- high 8 bytes in little-endian

    local payload = buf:getBytes() + 14 + 20 + 8 + 16
    if msgData.encrypted_data ~= payload then
        return "offset calculation fail"
    end
    if buf:getSize() ~= pkt.ip4:getLength() + 14 then
        return "buf size != ip length: " .. buf:getSize() .. " " .. pkt.ip4:getLength()
    end
    local err = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
        payload, nil, -- cipertext (dst)
        payload, innerL3Len, -- plaintext (src)
        nil, 0,  -- addition data (unused)
        nil, -- nsec (unused)
        nonce, key
    )
    if err ~= 0 then
        return "Error encrypting packet: " .. err
    end
    return nil
end

return wg

-- ffi.cdef[[
--     enum curve25519_lengths {
--         CURVE25519_POINT_SIZE = 32
--     };

--     enum chacha20poly1305_lengths {
--         XCHACHA20POLY1305_NONCELEN = 24,
--         CHACHA20POLY1305_KEYLEN = 32,
--         CHACHA20POLY1305_AUTHTAGLEN = 16
--     };

--     enum blake2s_lengths {
--         BLAKE2S_BLOCKBYTES = 64,
--         BLAKE2S_OUTBYTES = 32,
--         BLAKE2S_KEYBYTES = 32
--     };

--     enum noise_lengths {
--         NOISE_PUBLIC_KEY_LEN = CURVE25519_POINT_SIZE,
--         NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEYLEN,
--         NOISE_TIMESTAMP_LEN = sizeof(uint64_t) + sizeof(uint32_t),
--         NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAGLEN,
--         NOISE_HASH_LEN = BLAKE2S_OUTBYTES
--     };

--     // #define noise_encrypted_len(plain_len) (plain_len + NOISE_AUTHTAG_LEN)

--     // Helper definitions
--     enum {
--         HZ = 100,
--         BITS_PER_LONG = sizeof(unsigned long) * 8,
--         UINT64_MAX = 18446744073709551615ull
--     };

--     enum cookie_values {
--         COOKIE_SECRET_MAX_AGE = 2 * 60 * HZ,
--         COOKIE_SECRET_LATENCY = 5 * HZ,
--         COOKIE_NONCE_LEN = XCHACHA20POLY1305_NONCELEN,
--         COOKIE_LEN = 16
--     };

--     enum counter_values {
--         COUNTER_BITS_TOTAL = 2048,
--         COUNTER_REDUNDANT_BITS = BITS_PER_LONG,
--         COUNTER_WINDOW_SIZE = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS
--     };
    
--     enum limits {
--         REKEY_AFTER_MESSAGES = UINT64_MAX - 0xffff,
--         REJECT_AFTER_MESSAGES = UINT64_MAX - COUNTER_WINDOW_SIZE - 1,
--         REKEY_TIMEOUT = 5 * HZ,
--         REKEY_TIMEOUT_JITTER_MAX = HZ / 3,
--         REKEY_AFTER_TIME = 120 * HZ,
--         REJECT_AFTER_TIME = 180 * HZ,
--         INITIATIONS_PER_SECOND = HZ / 50,
--         MAX_PEERS_PER_DEVICE = 1U << 20,
--         KEEPALIVE_TIMEOUT = 10 * HZ,
--         MAX_TIMER_HANDSHAKES = (90 * HZ) / REKEY_TIMEOUT,
--         MAX_QUEUED_INCOMING_HANDSHAKES = 4096, /* TODO: replace this with DQL */
--         MAX_STAGED_PACKETS = 128,
--         MAX_QUEUED_PACKETS = 1024 /* TODO: replace this with DQL */
--     };

    -- enum message_type {
    --     MESSAGE_INVALID = 0,
    --     MESSAGE_HANDSHAKE_INITIATION = 1,
    --     MESSAGE_HANDSHAKE_RESPONSE = 2,
    --     MESSAGE_HANDSHAKE_COOKIE = 3,
    --     MESSAGE_DATA = 4
    -- };

--     struct message_header {
--         /* The actual layout of this that we want is:
--          * u8 type
--          * u8 reserved_zero[3]
--          *
--          * But it turns out that by encoding this as little endian,
--          * we achieve the same thing, and it makes checking faster.
--          */
--         __le32 type;
--     };

--     struct message_macs {
--         u8 mac1[COOKIE_LEN];
--         u8 mac2[COOKIE_LEN];
--     };

--     struct message_handshake_initiation {
--         struct message_header header;
--         __le32 sender_index;
--         u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
--         u8 encrypted_static[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
--         u8 encrypted_timestamp[noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
--         struct message_macs macs;
--     };

--     struct message_handshake_response {
--         struct message_header header;
--         __le32 sender_index;
--         __le32 receiver_index;
--         u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
--         u8 encrypted_nothing[noise_encrypted_len(0)];
--         struct message_macs macs;
--     };

--     struct message_handshake_cookie {
--         struct message_header header;
--         __le32 receiver_index;
--         u8 nonce[COOKIE_NONCE_LEN];
--         u8 encrypted_cookie[noise_encrypted_len(COOKIE_LEN)];
--     };

    -- struct message_data {
    --     struct message_header header;
    --     __le32 key_idx;
    --     __le64 counter;
    --     u8 encrypted_data[];
    -- };

--     #define message_data_len(plain_len) (noise_encrypted_len(plain_len) + sizeof(struct message_data))

--     enum message_alignments {
--         MESSAGE_PADDING_MULTIPLE = 16,
--         MESSAGE_MINIMUM_LENGTH = message_data_len(0)
--     };

--     #define SKB_HEADER_LEN (max(sizeof(struct iphdr), sizeof(struct ipv6hdr)) + sizeof(struct udphdr) + NET_SKB_PAD)
--     #define DATA_PACKET_HEAD_ROOM ALIGN(sizeof(struct message_data) + SKB_HEADER_LEN, 4)

--     enum {
--         HANDSHAKE_DSCP = 0x88 /* AF41, plus 00 ECN */
--     };
-- ]]
