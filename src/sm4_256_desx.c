#include "sm4.h"
#include <string.h>
#include "sm4_256_desx.h"
int sm4_256_set_key_desx(const uint8_t *key,SM4_KEY *ks){
	
	return ossl_sm4_set_key(key,ks);
	
	}

void sm4_256_encrypt_desx(uint8_t *in,uint8_t *out,const uint8_t *key,SM4_KEY *ks){

	int len = strlen(in);
	if(len>block_size) len = block_size; //cuz the sm4_128 encryption is for 16 bytes.
	
	uint8_t *in_x = (uint8_t *)calloc(len,sizeof(uint8_t));
	
	int i,j;
	for(i=0;i<len;i++){
		
		in_x[i] = in[i]^key[128+i];
		
		}
	ossl_sm4_encrypt(in_x,out,ks);
	for(i=0;i<len;i++){
		out[i] = out[i]^key[128+i];
		}
	free(in_x);
}

void sm4_256_decrypt_desx(uint8_t *in,uint8_t *out,const uint8_t *key,SM4_KEY *ks){
	
	int len = strlen(in);
	if(len>block_size) len = block_size;
	
	uint8_t *in_x = (uint8_t *)calloc(len,sizeof(uint8_t));
	int i,j;
	for(i=0;i<len;i++){
		
		in_x[i] = in[i]^key[128+i];
		
		}
	ossl_sm4_decrypt(in_x,out,ks);	
	for(i=0;i<len;i++){
		
		out[i] = out[i]^key[128+i];
		
		}
	free(in_x);	
	}


