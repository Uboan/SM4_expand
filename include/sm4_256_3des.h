#include "sm4.h"
#include <stdlib.h>
#include "sm4_expand.h"
typedef struct SM4_3des_KEY_st{
	SM4_KEY *KEY[2];
	}SM4_3des_KEY;


void sm4_256_set_key_3des(const uint8_t *key, SM4_3des_KEY *ks);
	
	
void sm4_256_encrypt_3des(const uint8_t *in, uint8_t *out, const SM4_3des_KEY *ks);
	

void sm4_256_decrypt_3des(const uint8_t *in, uint8_t *out, const SM4_3des_KEY *ks);

void sm4_3des_ctr_inc(unsigned char *counter);
void sm4_3des_ctr_encrypt( const char *in,//the data in must be times of 16 bytes
							char *out,
							int len,
							const void *key,SM4_3des_KEY *ks,
							unsigned char ivec[16],//only uses the lower 64 bit of ivec as counter
							unsigned char ecount_buf[16],
							unsigned int num,//(*num)
							int Cypher);//缺省值

void sm4_3des_cbc_encrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_3des_KEY *ks);

void sm4_3des_cbc_decrypt(uint8_t *in,uint8_t *out,uint8_t *ivec,size_t len,SM4_3des_KEY *ks);
