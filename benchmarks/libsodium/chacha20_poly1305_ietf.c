#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <sodium.h>

// TODO: also measure failure times

static void handler(union sigval sv) {
    volatile sig_atomic_t *flag = sv.sival_ptr;
    *flag = false;
}

static timer_t setup_timer(void *flag) {
    timer_t timerid;

    struct sigevent sev = {
        .sigev_notify = SIGEV_THREAD,
        .sigev_signo = 0,
        .sigev_value.sival_ptr = flag,
        .sigev_notify_function = handler,
        .sigev_notify_attributes = NULL,
    };

    int err = timer_create(CLOCK_MONOTONIC, &sev, &timerid);
    if (err) {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    return timerid;
}

static void reset_timer(timer_t timerid) {
    struct itimerspec its = {
        .it_value.tv_sec = 10,
        .it_value.tv_nsec = 0
    };
    int err = timer_settime(timerid, 0, &its, NULL);
    if (err) {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }
}

int main(void) {
    if (sodium_init() == -1) {
        return 1;
    }

    volatile sig_atomic_t running = true;
    timer_t t = setup_timer((void*) &running);

    struct timespec t1, t2;

    uint8_t key[crypto_aead_chacha20poly1305_IETF_KEYBYTES] = {};
    uint8_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {};
    uint8_t* message;
    uint8_t* ciphertext;
    uint8_t* decrypted;

    crypto_aead_chacha20poly1305_ietf_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));

    size_t block_sizes[] = {8, 16, 32, 64, 128, 256, 512, 1280, 1514, 2048, 8000, 15 * 1024, 64 * 1024};

    printf("# block_size, enc_operations_per_second, enc_Mbits_per_second, dec_operations_per_second, dec_Mbits_per_second\n");

    for (size_t i = 0; i < sizeof(block_sizes) / sizeof(*block_sizes); i++) {
        // Init
        const size_t bs = block_sizes[i];
        message = malloc(bs);
        ciphertext = malloc(bs + crypto_aead_chacha20poly1305_IETF_ABYTES);

        // Bench encryption
        running = true;
        uint64_t runs = 0;
        reset_timer(t);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while (running) {
            sodium_increment(nonce, sizeof(nonce));
            crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL,
                    message, bs,
                    NULL, 0,
                    NULL, nonce, key);
            sodium_increment(nonce, sizeof(nonce)); crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, message, bs, NULL, 0, NULL, nonce, key);
            sodium_increment(nonce, sizeof(nonce)); crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, message, bs, NULL, 0, NULL, nonce, key);
            sodium_increment(nonce, sizeof(nonce)); crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, message, bs, NULL, 0, NULL, nonce, key);
            sodium_increment(nonce, sizeof(nonce)); crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, message, bs, NULL, 0, NULL, nonce, key);
            sodium_increment(nonce, sizeof(nonce)); crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, message, bs, NULL, 0, NULL, nonce, key);
            sodium_increment(nonce, sizeof(nonce)); crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, message, bs, NULL, 0, NULL, nonce, key);
            sodium_increment(nonce, sizeof(nonce)); crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, message, bs, NULL, 0, NULL, nonce, key);
            runs += 8;
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        uint64_t elapsed_enc = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        double secs_enc = elapsed_enc / 1e9;
        double ops_enc = runs / secs_enc;
        double mbpps_enc = (bs * runs * 8) / (secs_enc * 1e6);

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

        // Bench decryption
        sodium_increment(nonce, sizeof(nonce));
        crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, message, bs, NULL, 0, NULL, nonce, key);
        running = true;
        runs = 0;
        reset_timer(t);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        while (running) {
            crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL, NULL, ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES, NULL, 0, nonce, key);
            crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL, NULL, ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES, NULL, 0, nonce, key);
            crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL, NULL, ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES, NULL, 0, nonce, key);
            crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL, NULL, ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES, NULL, 0, nonce, key);
            crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL, NULL, ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES, NULL, 0, nonce, key);
            crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL, NULL, ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES, NULL, 0, nonce, key);
            crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL, NULL, ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES, NULL, 0, nonce, key);
            crypto_aead_chacha20poly1305_ietf_decrypt(message, NULL, NULL, ciphertext, bs + crypto_aead_chacha20poly1305_IETF_ABYTES, NULL, 0, nonce, key);            
            runs += 8;
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);

        uint64_t elapsed_dec = (t2.tv_nsec + t2.tv_sec * 1e9) - (t1.tv_nsec + t1.tv_sec * 1e9);
        double secs_dec = elapsed_dec / 1e9;
        double ops_dec = runs / secs_dec;
        double mbpps_dec = (bs * runs * 8) / (secs_dec * 1e6);

        printf("%zu, %.2lf, %.2lf, %.2lf, %.2lf\n", bs, ops_enc, mbpps_enc, ops_dec, mbpps_dec);

        // Cleanup
        free(message);
        free(ciphertext);
    }
    timer_delete(t);
}
