/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


# pragma once

#include <stdint.h>

# define SM4_ENCRYPT     1
# define SM4_DECRYPT     0

# define SM4_BLOCK_SIZE    16
# define SM4_KEY_SCHEDULE  44

typedef struct SM4_EXPAND_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_EXPAND_KEY;

int sm4_expand_set_key(const uint8_t *key, SM4_EXPAND_KEY *ks);



void sm4_expand_encrypt(const uint8_t *in, uint8_t *out, const SM4_EXPAND_KEY *ks);

void sm4_expand_decrypt(const uint8_t *in, uint8_t *out, const SM4_EXPAND_KEY *ks);



