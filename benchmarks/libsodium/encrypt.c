#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <sodium.h>

bool inplace = false;
const size_t runs = 1 << 21;

int main(void) {
    if (sodium_init() == -1) {
        return 1;
    }

    struct timespec t1, t2;

    uint8_t key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    uint8_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {};
    uint8_t* message;
    uint8_t* ciphertext;
    uint8_t* decrypted;

    crypto_aead_chacha20poly1305_ietf_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));

    size_t block_sizes[] = {60, 128, 256, 512, 1280, 1514};

    printf("# block_size, elapsed_seconds, operations_per_second, Mbits_per_second\n");

    for (size_t i = 0; i < sizeof(block_sizes) / sizeof(*block_sizes); i++) {
        // Init
        const size_t bs = block_sizes[i];
        if (inplace) {
            message = malloc(bs + crypto_aead_chacha20poly1305_IETF_ABYTES);
            ciphertext = message;
        } else {
            message = malloc(bs);
            ciphertext = malloc(bs + crypto_aead_chacha20poly1305_IETF_ABYTES);
        }


        // Bench
        clock_gettime(CLOCK_MONOTONIC, &t1);
        for (size_t i = 0; i < runs; i++) {
            sodium_increment(nonce, sizeof(nonce));
            crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL,
                    message, bs,
                    NULL, 0,
                    NULL, nonce, key);
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        uint64_t elapsed = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        double secs = elapsed / 1e9;
        double ops = runs / secs;
        double mbpps = (bs * runs * 8) / (secs * 1e6);
        printf("%zu, %.2lf, %.2lf, %.2lf\n", bs, secs, ops, mbpps);

        // Consistency check
        int err = crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL,
                NULL,
                ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES,
                NULL, 0,
                nonce, key);

        if (err != 0) {
            fprintf(stderr, "Message decryption failed!\n");
            exit(1);
        }

        // Cleanup
        if (inplace) {
            free(message);
        } else {
            free(message);
            free(ciphertext);
        }
    }
}