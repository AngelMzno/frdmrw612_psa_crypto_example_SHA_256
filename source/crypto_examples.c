/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "psa/crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/sha256.h"

#include "fsl_debug_console.h"
#include "board.h"
#include "app.h"

void print_hash(const unsigned char *hash, size_t len) {
    for (size_t i = 0; i < len; i++) {
        PRINTF("%02x ", hash[i]);
    }
    PRINTF("\n\r");
}

void attempt_decrypt(const unsigned char *hash, size_t hash_len) {
    // Attempt to "decrypt" the hash (this will fail)
    unsigned char decrypted[32];
    memcpy(decrypted, hash, hash_len);
    PRINTF("Decrypted message (incorrect): ");
    for (size_t i = 0; i < hash_len; i++) {
        PRINTF("%c", decrypted[i]);
    }
    PRINTF("\n\r");
}

//SHA-256 is a cryptographic hash function that produces a fixed-size (256-bit) hash value from variable-size input data.

int main() {
    // Initialize the debug console
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    // Message to hash
    unsigned char input[] = "BBVA_password";
    size_t input_len = strlen((const char *)input);
    unsigned char output[32]; // SHA-256 produces a 32-byte hash

    PRINTF("Input message: %s\n\r", input);

    // Initialize context
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, input, input_len);
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);

    // Show results
    PRINTF("SHA-256 hash: ");
    print_hash(output, sizeof(output));

    // Demonstrate why SHA-256 is not cyclic
    PRINTF("Attempting to 'decrypt' the hash...\n\r");
    attempt_decrypt(output, sizeof(output));
    PRINTF("Decryption failed: SHA-256 is a one-way hash function and cannot be decrypted.\n\r");
    
    return 0;
}
