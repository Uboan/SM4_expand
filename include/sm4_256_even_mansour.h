# pragma once
#include <stdint.h>
#include "sm4.h"

#define block_size 16

int sm4_256_set_key_even_mansour(const uint8_t *key,SM4_KEY *ks);

void sm4_256_encrypt_even_mansour(uint8_t *in,uint8_t *out,uint8_t *key,SM4_KEY *ks);

void sm4_256_decrypt_even_mansour(uint8_t *in,uint8_t *out,uint8_t *key,SM4_KEY *ks);
