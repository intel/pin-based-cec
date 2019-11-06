/* Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "../include/pin_based_cec.h"

#define AES128_KEY_SIZE_IN_DWORDS                                               4
#define AES128_KEY_SIZE_IN_BYTES    (AES128_KEY_SIZE_IN_DWORDS * sizeof(uint32_t))
#define AES128_NUM_ROUNDS                                                       11

static uint32_t AES128_RCON[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
};

static uint8_t AES_SBOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

uint32_t rot_word(uint32_t word) {
    uint8_t b0 = (word & 0xFF000000) >> 24;
    return (word << 8) | b0;
}

uint32_t sub_word(uint32_t word) {
    uint8_t b0 = (word >> 24) & 0xFF;
    uint8_t b1 = (word >> 16) & 0xFF;
    uint8_t b2 = (word >>  8) & 0xFF;
    uint8_t b3 = (word      ) & 0xFF;

    uint8_t s0 = AES_SBOX[b0];
    uint8_t s1 = AES_SBOX[b1];
    uint8_t s2 = AES_SBOX[b2];
    uint8_t s3 = AES_SBOX[b3];

    return ((uint32_t)s0 << 24) | ((uint32_t)s1 << 16) | ((uint32_t)s2 << 8) | s3;
}

// Naive implementation of AES-128 key expansion.
void aes128_key_expansion(const uint32_t* key, uint32_t* key_schedule) {
    for (uint32_t i = 0; i < 4 * AES128_NUM_ROUNDS; i++) {
        if (i < AES128_KEY_SIZE_IN_DWORDS) {
            key_schedule[i] = key[i];
        } else if ((i >= AES128_KEY_SIZE_IN_DWORDS) && (i % AES128_KEY_SIZE_IN_DWORDS == 0)) {
            key_schedule[i] = key_schedule[i - AES128_KEY_SIZE_IN_DWORDS] ^ sub_word(rot_word(key_schedule[i - 1])) ^ AES128_RCON[i / AES128_KEY_SIZE_IN_DWORDS - 1];
        } else {
            key_schedule[i] = key_schedule[i - AES128_KEY_SIZE_IN_DWORDS] ^ key_schedule[i - 1];
        }
    }
}

// Example for detecting a branch
// Compute the checksum of the key
// Note: Just a demonstration of a rare branch that may be tainted.
// Do NOT implement a checksum in this manner
uint32_t aes128_key_checksum(const uint32_t * key) {
    uint32_t checksum = 0;
    for (uint32_t i = 0; i < AES128_KEY_SIZE_IN_DWORDS; i++) {
        checksum ^= key[i];
    }
    // This is a rare branch that has a low probability of being hit in tests
    if (checksum == 0) {
        checksum = 1;
    }
    return checksum;
}

int main(void) {
    for (uint32_t iter = 0; iter < 10; iter++) {

        // Allocate memory for our secret key.
        uint32_t* key = (uint32_t*)malloc(AES128_KEY_SIZE_IN_BYTES);
        if (key == NULL) {
            printf("Error: couldn't allocate memory.\n");
            return 1;
        }

        // Allocate some memory that will hold our key schedule (the result of key expansion).
        uint32_t* key_schedule = (uint32_t*)malloc(4 * AES128_NUM_ROUNDS * sizeof(uint32_t));
        if (key_schedule == NULL) {
            printf("Error: couldn't allcoate memory.\n");
            return 1;
        }

        // Generate a random key.
        FILE* rng = fopen("/dev/urandom", "r");
        if (rng == NULL) {
            printf("Error: couldn't open /dev/urandom.\n");
            return 1;
        }

        size_t num_bytes = fread(key, sizeof(uint8_t), AES128_KEY_SIZE_IN_BYTES, rng);
        fclose(rng);
        if (num_bytes != AES128_KEY_SIZE_IN_BYTES) {
            printf("Error: couldn't get random data.\n");
            return 1;
        }

        // Print the generated key.
        printf("Key: ");
        for (uint32_t i = 0; i < AES128_KEY_SIZE_IN_DWORDS; i++) {
            printf("%08X ", key[i]);
        }
        printf("\n");

        // Mark the memory location of the key as a secret, so that Pin-based CEC can track it.
        PinBasedCEC_MarkSecret((uint64_t)key, AES128_KEY_SIZE_IN_BYTES);

        // Call the function to expand the key to fill the key schedule.
        aes128_key_expansion((const uint32_t*)key, key_schedule);

        // Call the function to compute the checksum
        uint32_t checksum = aes128_key_checksum(key);

        // Tell Pin-based CEC that we are done using all the secrets we marked earlier, so it can stop tracking them.
        PinBasedCEC_ClearSecrets();

        // Print the expanded key.
        printf("Key schedule:\n");
        for (uint32_t i = 0; i < AES128_NUM_ROUNDS; i++) {
            printf("\t");
            for (uint32_t j = 0; j < AES128_KEY_SIZE_IN_DWORDS; j++) {
                printf("%08X ", key_schedule[i*AES128_KEY_SIZE_IN_DWORDS + j]);
            }
            printf("\n");
        }
        printf("\n");

        printf("Checksum: %08X\n", checksum);

        // Cleanup our allocations.
        free(key);
        free(key_schedule);
    }

    return 0;
}
