/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-06-07 16:38:06
 * @LastEditTime : 2022-06-07 19:08:14
 * @FilePath     : \sm4_256_desx\sm4_256_3des.c
 */
#include "sm4_256_3des.h" 


void sm4_256_set_key_3des(const uint8_t *key, SM4_3des_KEY *ks){
	ks->KEY[0] = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	ks->KEY[1] = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	ossl_sm4_set_key(key,ks->KEY[0]);
	ossl_sm4_set_key(key+16,ks->KEY[1]);
	
	
	}
	
	
void sm4_256_encrypt_3des(const uint8_t *in, uint8_t *out, const SM4_3des_KEY *ks){
	uint8_t *in_tmp = (uint8_t *)calloc(SM4_BLOCK_SIZE,sizeof(uint8_t));
	
	ossl_sm4_encrypt(in,out,ks->KEY[0]);
	ossl_sm4_decrypt(out,in_tmp,ks->KEY[1]);
	ossl_sm4_encrypt(in_tmp,out,ks->KEY[0]);
	free(in_tmp);	
	};
	

void sm4_256_decrypt_3des(const uint8_t *in, uint8_t *out, const SM4_3des_KEY *ks){
	uint8_t *in_tmp = (uint8_t *)calloc(SM4_BLOCK_SIZE,sizeof(uint8_t));
	
	ossl_sm4_decrypt(in,in_tmp,ks->KEY[0]);
	ossl_sm4_encrypt(in_tmp,in_tmp,ks->KEY[1]);
	ossl_sm4_decrypt(in_tmp,out,ks->KEY[0]);
	free(in_tmp);
	
	
	}
