# pragma once
#include "sm4_256_lai_massey.h"
#include <stdint.h>
#include <stdio.h>

void sm4_256_LM_cbc_set_key(const uint8_t *key2,SM4_KEY *ks);

void sm4_256_LM_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,uint8_t *key1,SM4_KEY *ks);

void sm4_256_LM_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_KEY *ks);

