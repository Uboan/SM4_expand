#include <stdio.h>
#include "sm4.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include "sm4_256_desx.h"
#include "pksc7_padding.h"
#include "util.h"


#include "sm4_256_3des.h"

//use the first 128 bits as the Key and the rest as key1

#define TEST 1000000




int main323()// padding with pksc7 testing
{

	#if 0
	uint8_t key[] = {"1234567890123456"}; 
	uint8_t in[] = {"123456789ABCDEFGH"}; 
	uint8_t out[32],out2[32]; 
	SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	ossl_sm4_set_key(key,ks);
	ossl_sm4_encrypt(in,out,ks);
	printf("%s\n",out);
	ossl_sm4_decrypt(out,out2,ks);
	printf("%s\n",out2);
	return 0;
	#endif
	
	
	
	uint8_t key[] = {"1234567890123456"};
	uint8_t a[] = {"gyhjiug"};
	
	SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));

	uint8_t *ap,*as,*out,*out2;
	ap = pksc7_padding(a);
	printf("padding:\nsize:%d\n%s\n",strlen(ap),ap);
	
	ossl_sm4_set_key(key,ks);
	
	out = (uint8_t*)calloc(strlen(ap),sizeof(uint8_t));
	out2 = (uint8_t*)calloc(strlen(ap),sizeof(uint8_t));

	ossl_sm4_encrypt(ap,out,ks);
	
	
	
	printf("\nsize:%d\n%s\n",strlen(out),out);
	ossl_sm4_decrypt(out,out2,ks);
	printf("%s\n",out2);
	
	as = pksc7_stripping(out2);
	printf("stripping:\nsize:%d\n%s\n",strlen(as),as);

	return 0;
	
}

#if 0
int main33(){
	uint8_t key[] = {"12345678901234561234567890123456"};
	AES_KEY *ks = (AES_KEY*)malloc(sizeof(AES_KEY));
	int i;
	uint64_t starttime,endtime,ans;
	uint8_t in[] = {"123456789ABCDEFGH"}; 
	uint8_t out[32] = {0x00},out2[32] = {0x00}; 
	
	AES_set_encrypt_key(key,256,ks);
	starttime = start_rdtsc();
	
	for(i=0;i<TEST;i++)
		AES_encrypt(in,out,ks);
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	printf("AES-256 method:\n Encryption circles/byte(256):%llu\n",ans/(TEST*16));
	AES_set_decrypt_key(key,256,ks);
	
	starttime = start_rdtsc();
	for(i=0;i<TEST;i++)
		AES_decrypt(out,out2,ks);
	endtime = end_rdtsc();
	ans = endtime - starttime;
	printf("AES-256 Decryption circles/byte(128):%llu\n",ans/(TEST*16));
	printf("AES-256 Decrypted data: %s\n",out2);
	
	
	
	

	
	
	
	return 0;
	}
	#endif

int main_sm4(){// test padding and sm4_256_desx with comparison of normal sm4(128)
	
	
	uint8_t key[] = {"12345678901234561234567890123456"}; 

	SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	SM4_KEY *ks_128 = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	uint8_t a[] = {"gy231edasftug"};
	
	uint8_t *ap,*ap2,*as,*out,*out_256,*out2;
	
	uint64_t starttime,endtime,ans;
	
	int i,j;
	
	ap = pksc7_padding(a);
	ap2 = (uint8_t *)calloc(strlen(ap),sizeof(uint8_t));
	strcpy(ap2,ap);//a copy of ap
	
	printf("padding:\nsize:%d\n%s\n",strlen(ap),ap);
	
	out = (uint8_t *)calloc(strlen(ap),sizeof(uint8_t));
	out_256 = (uint8_t *)calloc(strlen(ap),sizeof(uint8_t));
	out2 = (uint8_t *)calloc(strlen(ap),sizeof(uint8_t));
	sm4_256_set_key_desx(key,ks);
	
	
	uint8_t key_128[] = {"1234567890123456"};
	
	ossl_sm4_set_key(key_128,ks);
	
	////////////////////////////////////////////////
	
	#if 0//Encryption of desx
	starttime = start_rdtsc();
	
	for(i=0;i<TEST;i++)
		sm4_256_encrypt_desx(ap2,out_256,key,ks);
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	printf("Desx method:\n Encryption circles/byte(256):%llu\n",ans/(TEST*16));

	starttime = start_rdtsc();
	for(i=0;i<TEST;i++)
		sm4_256_decrypt_desx(out_256,out2,key,ks);
	endtime = end_rdtsc();
	ans = endtime - starttime;
	printf("desx Decryption circles/byte(128):%llu\n",ans/(TEST*16));
	printf("desx Decrypted data: %s\n",out2);
	#endif 
	///////////////////////////////////////////////////
	
	
	//////////////////////////////////////////////////
	#if 1
	starttime = start_rdtsc();// test normal 128
	
	for(i=0;i<TEST;i++)
		ossl_sm4_encrypt(ap,out,ks);
	
	
	endtime = end_rdtsc();
	ans = endtime - starttime;
	printf("Normal Encryption circles/byte(128):%llu\n",ans/(TEST*16));
	
	starttime = start_rdtsc();
	for(i=0;i<TEST;i++)
		ossl_sm4_decrypt(out,out2,ks);
	
	endtime = end_rdtsc();
	ans = endtime - starttime;
	printf("normal Decryption circles/byte(128):%llu\n",ans/(TEST*16));
	printf("normal Decrypted data: %s\n",out2);
	
	#endif
	/////////////////////////////////////////////////
	
	
	

	
	as = pksc7_stripping(out2);
	printf("Stripped data: %s\n",as);
	
	
	return 0;
}


int main11(){// test sm4_256_3des 
	
	uint8_t key[] = {"12345678901234561234567890123456"}; 
	
	uint64_t starttime,endtime,ans;
	SM4_3des_KEY *ks = (SM4_3des_KEY*)malloc(sizeof(SM4_3des_KEY));;
	int i;
	sm4_256_set_key_3des(key,ks);
	uint8_t in[] = {"123456789ABCDEFGH"}; 
	uint8_t out[32] = {0x00},out2[32] = {0x00}; 
	
	
	printf("original data: %s\n",in);
	
	
	
	
	starttime = start_rdtsc();
	
	for(i=0;i<TEST;i++)
		sm4_256_encrypt_3des(in,out,ks);
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	printf("circles/byte(256) encryption:%llu\n",ans/(TEST*16));
	
	
	
	//printf("encrypted data with 3des method : %s\n,  length of it is %d\n",out,strlen(out));
	
	starttime = start_rdtsc();
	
	for(i=0;i<TEST;i++)
		sm4_256_decrypt_3des(out,out2,ks);
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	printf("circles/byte(256) decryption:%llu\n",ans/(TEST*16));
	
	
	//printf("decrypted data with 3des method : %s,  length of it is %d\n",out2,strlen(out2));
	
	
	return 3;
	}
