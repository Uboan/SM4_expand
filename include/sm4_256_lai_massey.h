# pragma once
#include <stdint.h>
#include "sm4.h"
#include "util.h"

#define block_size 16

int sm4_256_set_key_lai_massey(const uint8_t *key,SM4_KEY *ks);

void sm4_256_encrypt_lai_massey(uint8_t *inL,uint8_t *inR,uint8_t *outL,uint8_t *outR,SM4_KEY *ks);

void sm4_256_decrypt_lai_massey(uint8_t *inL,uint8_t *inR,uint8_t *outL,uint8_t *outR,SM4_KEY *ks);

