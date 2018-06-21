#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint8_t our_private[] = {0x58, 0x09, 0xa0, 0x55, 0x85, 0xe4, 0x6d, 0x3d, 0x9b, 0x0a, 0xd7, 0x5c, 0x0f, 0x0a, 0x25, 0x23, 0xcf, 0x3f, 0x89, 0x58, 0xbf, 0x69, 0x5d, 0xff, 0x3c, 0x77, 0x14, 0x05, 0x34, 0x12, 0x62, 0x6a};
const uint8_t our_public[] = {0x2b, 0x9b, 0x05, 0xf7, 0x21, 0x12, 0xad, 0x20, 0x6c, 0x39, 0x73, 0xdd, 0xe9, 0x37, 0x29, 0x28, 0xd8, 0x2a, 0xa3, 0x2d, 0x48, 0x93, 0x76, 0x45, 0x2a, 0x5e, 0x05, 0xa2, 0x5c, 0xeb, 0x47, 0x22};
const uint8_t their_public[] = {0xa9, 0x10, 0xb0, 0x65, 0x22, 0x88, 0x9e, 0xb3, 0x00, 0xab, 0x9b, 0x1e, 0xa5, 0xf0, 0x9d, 0x68, 0x2b, 0x11, 0x25, 0xaa, 0x0b, 0x7b, 0x98, 0xe1, 0xb7, 0x37, 0xe2, 0xc3, 0xb0, 0xa3, 0x6f, 0x03};
const uint8_t preshared[] = {0x16, 0x90, 0xb2, 0x87, 0x0b, 0x3d, 0x73, 0x1c, 0x16, 0xa1, 0x5e, 0x31, 0x10, 0xbb, 0x5f, 0x26, 0xf8, 0xc9, 0x37, 0xec, 0xd0, 0x55, 0x13, 0xc8, 0x4a, 0x59, 0x51, 0x5a, 0x07, 0xa8, 0xa5, 0x51};

int main(int argc, char const *argv[]) {
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }

    const char protocol[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    const char prologue[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";

    NoiseHandshakeState *handshake;

    int err = noise_handshakestate_new_by_name(&handshake, protocol, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    err = noise_handshakestate_set_prologue(handshake, prologue, strlen(prologue));
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    err = noise_handshakestate_set_pre_shared_key(handshake, preshared, 32);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    NoiseDHState *dh;

    dh = noise_handshakestate_get_remote_public_key_dh(handshake);
    if (noise_dhstate_get_public_key_length(dh) != 32) {
        fprintf(stderr, "Unexpected key length\n");
        return 1;
    }
    err = noise_dhstate_set_public_key(dh, their_public, 32);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    dh = noise_handshakestate_get_local_keypair_dh(handshake);
    if (noise_dhstate_get_private_key_length(dh) != 32) {
        fprintf(stderr, "Unexpected key length\n");
        return 1;
    }
    err = noise_dhstate_set_keypair(dh, our_private, 32, their_public, 32);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(protocol, err);
        return 1;
    }

    

    uint8_t buf[64] = {};
    buf[0] = 1; // Type: Initiation

    buf[7] = 28; // Sender index

    return 0;
}
