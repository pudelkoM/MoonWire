local ffi = require "ffi"
local C = ffi.C
local sodiumlib = ffi.load("./src/libsodium/build/lib/sodium")

local module = {}

ffi.cdef[[
    int sodium_init(void);

    void randombytes_buf(void * const buf, const size_t size);

    void sodium_increment(unsigned char *n, const size_t nlen);

    size_t crypto_aead_chacha20poly1305_ietf_keybytes(void);

    size_t crypto_aead_chacha20poly1305_ietf_npubbytes(void);

    size_t crypto_aead_chacha20poly1305_ietf_abytes(void);

    int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *c,
                                              unsigned long long *clen,
                                              const unsigned char *m,
                                              unsigned long long mlen,
                                              const unsigned char *ad,
                                              unsigned long long adlen,
                                              const unsigned char *nsec,
                                              const unsigned char *npub,
                                              const unsigned char *k);

    int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m,
                                              unsigned long long *mlen,
                                              unsigned char *nsec,
                                              const unsigned char *c,
                                              unsigned long long clen,
                                              const unsigned char *ad,
                                              unsigned long long adlen,
                                              const unsigned char *npub,
                                              const unsigned char *k);
    
    int sodium_runtime_has_sse2(void);
    int sodium_runtime_has_sse3(void);
    int sodium_runtime_has_ssse3(void);
    int sodium_runtime_has_sse41(void);
    int sodium_runtime_has_avx(void);
    int sodium_runtime_has_avx2(void);
    int sodium_runtime_has_avx512f(void);
    int sodium_runtime_has_aesni(void);
]]

local log = require "log"
function module.log_CPU_features()
    log:info(string.format("libsodium: SSE2 %u, SSE3 %u, SSSE3 %u, SSE41 %u, AVX %u, AVX2 %u, AVX512f %u, AES-NI %u", 
        sodiumlib.sodium_runtime_has_sse2(),
        sodiumlib.sodium_runtime_has_sse3(),
        sodiumlib.sodium_runtime_has_ssse3(),
        sodiumlib.sodium_runtime_has_sse41(),
        sodiumlib.sodium_runtime_has_avx(),
        sodiumlib.sodium_runtime_has_avx2(),
        sodiumlib.sodium_runtime_has_avx512f(),
        sodiumlib.sodium_runtime_has_aesni()
    ))
end

function module.sodium_init()
    return sodiumlib.sodium_init()
end

function module.randombytes_buf(buf, size)
    sodiumlib.randombytes_buf(buf, size);
end

function module.sodium_increment(n, nlen)
    sodiumlib.sodium_increment(n, nlen)
end

function module.crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k)
    return sodiumlib.crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k)
end

function module.crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k)
    return sodiumlib.crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k)
end

module.crypto_aead_chacha20poly1305_IETF_KEYBYTES = sodiumlib.crypto_aead_chacha20poly1305_ietf_keybytes()
module.crypto_aead_chacha20poly1305_IETF_NPUBBYTES = sodiumlib.crypto_aead_chacha20poly1305_ietf_npubbytes()
module.crypto_aead_chacha20poly1305_IETF_ABYTES = sodiumlib.crypto_aead_chacha20poly1305_ietf_abytes()

return module
