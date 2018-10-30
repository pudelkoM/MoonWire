local sodium = require "sodium"
local ffi = require "ffi"
local lock = require "lock"
local dpdk_export = require "missing-dpdk-stuff"

local peerDef_pthreads = "struct peer_pthreads { \
    uint8_t rxKey[" .. tonumber(sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES) .. "]; \
    uint8_t txKey[" .. tonumber(sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES) .. "]; \
    uint8_t nonce[" .. tonumber(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES) .. "]; \
    uint32_t id; \
    struct lock* lock_; \
};"

local peerDef_rte_spinlock = "struct peer_rte_spinlock { \
    uint8_t rxKey[" .. tonumber(sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES) .. "]; \
    uint8_t txKey[" .. tonumber(sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES) .. "]; \
    uint8_t nonce[" .. tonumber(sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES) .. "]; \
    uint32_t id; \
    rte_spinlock_t lock_; \
};"

ffi.cdef(peerDef_pthreads)
ffi.cdef(peerDef_rte_spinlock)

local mod = {}

local peerCtr = 0

local peer_pthreads = {}
function peer_pthreads:lock()
    self.lock_:lock() -- pthreads
end
function peer_pthreads:unlock()
    self.lock_:unlock() -- pthreads
end
peer_pthreads.__index = peer_pthreads
ffi.metatype("struct peer_pthreads", peer_pthreads)

local peer_rte_spinlock = {}
function peer_rte_spinlock:lock()
    dpdk_export.rte_spinlock_lock_export(self.lock_)
end
function peer_rte_spinlock:unlock()
    dpdk_export.rte_spinlock_unlock_export(self.lock_)
end
peer_rte_spinlock.__index = peer_rte_spinlock
ffi.metatype("struct peer_rte_spinlock", peer_rte_spinlock)

-- chacha20
function mod.newPeer(type, rxKey, txKey, nonce)
    local obj
    if type == "rte" then
        obj = ffi.new("struct peer_rte_spinlock", {
            id = peerCtr
        })
        dpdk_export.rte_spinlock_init_export(obj.lock_)
    else
        obj = ffi.new("struct peer_pthreads", {
            id = peerCtr,
            lock_ = lock:new()
        })
    end
    
    if nonce then
        ffi.copy(obj.nonce, nonce, sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
    end
    ffi.fill(obj.nonce + 8, 4, 0) -- lower 4 bytes are 0 since counter is only 8 bytes

    if txKey then
        ffi.copy(obj.txKey, txKey, sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES)
    else
        ffi.fill(obj.txKey, sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES, 0xab) 
    end

    if rxKey then
        ffi.copy(obj.rxKey, rxKey, sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES)
    else
        ffi.fill(obj.rxKey, sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES, 0xef) 
    end

    peerCtr = peerCtr + 1
    return obj
end

return mod
