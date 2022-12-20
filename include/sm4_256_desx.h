
# pragma once

#include <stdint.h>

#define block_size 16

int sm4_256_set_key_desx(const uint8_t *key,SM4_KEY *ks);

void sm4_256_encrypt_desx(uint8_t *in,uint8_t *out,const uint8_t *key,SM4_KEY *ks);

void sm4_256_decrypt_desx(uint8_t *in,uint8_t *out,const uint8_t *key,SM4_KEY *ks);


