local ffi = require "ffi"
local C = ffi.C
local blake2sLib = ffi.load("./build/blake2s")

ffi.cdef[[
    int blake2s(void *out, size_t outlen, const void *key, size_t keylen, const void *in, size_t inlen);
    void blake2s_hmac(uint8_t *out, const uint8_t *in, const uint8_t *key, const size_t outlen, const size_t inlen, const size_t keylen);
]]

return blake2sLib