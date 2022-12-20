/*
 * @Date: 2022-11-02 02:28:28
 * @LastEditors: zyp
 * @LastEditTime: 2022-11-02 02:37:03
 * @FilePath: /sm4_256/include/sm4_256_EM_cbc.h
 * @Description: 
 * 
 * Copyright (c) 2022 by CBA511, All Rights Reserved. 
 */
# pragma once
#include "sm4_256_even_mansour.h"
#include <stdint.h>
#include <stdio.h>

void sm4_256_EM_cbc_set_key(const uint8_t *key2,SM4_KEY *ks);

void sm4_256_EM_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,uint8_t *key1,SM4_KEY *ks);

void sm4_256_EM_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,uint8_t *key1,SM4_KEY *ks);

