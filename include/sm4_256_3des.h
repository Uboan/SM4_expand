#include "sm4.h"

typedef struct SM4_3des_KEY_st{
	SM4_KEY *KEY[2];
	}SM4_3des_KEY;


void sm4_256_set_key_3des(const uint8_t *key, SM4_3des_KEY *ks);
	
	
void sm4_256_encrypt_3des(const uint8_t *in, uint8_t *out, const SM4_3des_KEY *ks);
	

void sm4_256_decrypt_3des(const uint8_t *in, uint8_t *out, const SM4_3des_KEY *ks);
