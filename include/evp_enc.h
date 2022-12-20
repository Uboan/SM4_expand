#include "sm4.h"
#include <stdint.h>

#define EVP_MAX_IV_LENGTH 256
#define EVP_MAX_BLOCK_LENGTH 256

typedef struct evp_cipher_st{
	int nid;// cipher algorithm ID
	int block_size;
	int key_len;
	int iv_len;
	unsigned long flags;
	//int (*init)(EVP_CIPHER_CTX )
	//int (*do_cipher)
	//int (*cleanup)
	int ctx_size;
	// int (*set_asn1_parameters)
	// int (*get_asn1_parameters)
	
	// int (*ctrl)
	void *app_data;
	}EVP_CIPHER;
	
typedef struct evp_cipher_ctx_st{
	
	const EVP_CIPHER *cipher;
	//ENGINE *engine;
	int encrypt;//the identity of encryption or decryption
	int buf_len;//the buffer size taken by this structure
	unsigned char oiv[EVP_MAX_IV_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char buf[EVP_MAX_BLOCK_LENGTH];
	int num;//the block size of processing in cfb/ofb mode
	void *app_data;//the data to process 
	int key_len;
	unsigned long flags;
	void *cipher_data;//data after the process
	int final_used;
	int block_mask;
	unsigned char final[EVP_MAX_BLOCK_LENGTH];

	}EVP_CIPHER_CTX;
	
void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);

int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);

	
int EVP_EncryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,int engine,//engine is a useless parameter
						const unsigned char *key,const unsigned char *iv);

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx,unsigned char *out,
						int *outl,const unsigned char *in, int inl);
						
int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);

int  EVP_DecryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,int engine,//engine is a useless parameter
						const unsigned char *key,const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx,unsigned char *out,
						int *outl,const unsigned char *in, int inl);
int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);

 
