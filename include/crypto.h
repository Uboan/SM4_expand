/*
 * @Date: 2022-11-01 23:59:31
 * @LastEditors: zyp
 * @LastEditTime: 2022-11-02 00:34:17
 * @FilePath: /sm4_256/include/crypto.h
 * @Description: 
 * 
 * Copyright (c) 2022 by CBA511, All Rights Reserved. 
 */

# pragma once
#include <stdint.h>
#include "sm4.h"
#include "sm4_256_even_mansour.h"
#include "sm4_256_lai_massey.h"

#define Lai_Massey 1
#define Even_Mansour 2
typedef struct SM4_256_KEY_t{
	SM4_KEY *ks128;
	uint8_t *key;
	int Cypher;//1 for Lai-Massey, 2 for even-mansour
	} SM4_256_KEY;


int set_key_lai_massey(const uint8_t *key,SM4_256_KEY *ks);
int sm4_256_set_key(const uint8_t *key,SM4_256_KEY *ks,int block);

void crypto_encrypt(uint8_t *in_data,uint8_t *out_data,SM4_256_KEY *ks,int block);
void crypto_decrypt(uint8_t *in_data,uint8_t *out_data,SM4_256_KEY *ks,int block);

////////////////////////////////////////////////////////////////////////////////////
/////////the cypher mode functions below have these parameter requirements//////////
//
//the in_data  must be times of 16 bytes
//the length of the out_data must be at least twice as large as in_data
//the in_data cannot be empty
//all the parameters must be allocated with memory first
void lai_massey_encrypt_ecb(const uint8_t *in_data,uint8_t *out_data,SM4_256_KEY *ks);
void lai_massey_decrypt_ecb(uint8_t *in_data,uint8_t *out_data,SM4_256_KEY *ks);

