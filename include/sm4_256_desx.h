
# pragma once
#include "sm4.h"
#include <stdint.h>
#include <stdlib.h>
#include "sm4_expand.h"
#define block_size 16

int sm4_256_set_key_desx(const uint8_t *key,SM4_KEY *ks);

void sm4_256_encrypt_desx(uint8_t *in,uint8_t *out,const uint8_t *key,SM4_KEY *ks);

void sm4_256_decrypt_desx(uint8_t *in,uint8_t *out,const uint8_t *key,SM4_KEY *ks);

void sm4_desx_ctr_inc(unsigned char *counter);
void sm4_desx_ctr_encrypt( const char *in,//the data in must be times of 16 bytes
							char *out,
							int len,
							const void *key,SM4_KEY *ks,
							unsigned char ivec[16],
							unsigned char ecount_buf[16],
							unsigned int num,//(*num)
							int Cypher);//缺省值
void sm4_desx_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,const void *key,SM4_KEY *ks);

void sm4_desx_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,const void *key,SM4_KEY *ks);
