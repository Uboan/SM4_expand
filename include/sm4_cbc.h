# pragma once
#include "sm4.h"
#include "sm4_expand.h"
#include <stdint.h>
#include <stdio.h>

void sm4_cbc_set_key(const uint8_t *key2,SM4_KEY *ks);

void sm4_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_KEY *ks);

void sm4_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_KEY *ks);

void sm4_expand_cbc_set_key(const uint8_t *key2,SM4_EXPAND_KEY *ks);

void sm4_expand_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_EXPAND_KEY *ks);

void sm4_expand_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_EXPAND_KEY *ks);

