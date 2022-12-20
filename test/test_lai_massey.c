
#include <stdio.h>
#include "sm4.h"
#include <stdlib.h>
#include <string.h>
#include "pksc7_padding.h"
#include "util.h"
#include "crypto.h"
#include "ctr_sm4_256.h"
#include "sm4_256_lai_massey.h"

#define TEST 1000000

int main21(){// test lai_massey
	
	uint8_t key[] = {"1234567890123456abcessdfghajqkwj"}; 
    uint8_t key1[] = {"abcessdfghajqkwj"}; 
	
	uint64_t starttime,endtime,ans;
	SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	int i;
	sm4_256_set_key_lai_massey(key,ks);
	uint8_t in[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,0x00};
	uint8_t out[32] = {0x00},out2[32] = {0x00}; 
	uint8_t outL[32] = {0x00}, outR[32] = {0x00};  
	uint8_t outLo[32] = {0x00}, outRo[32] = {0x00}; 
	printf("original data: %s\n",in);
	
	
	
	
	starttime = start_rdtsc();
	
	for(i=0;i<TEST;i++)
		sm4_256_encrypt_lai_massey(in,key1,outL,outR,ks);
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	printf("circles/byte(256) encryption:%llu\n",ans/(TEST*16));
	
	
	dump_hex(outL,16);
	printf("encrypted data with lai_massey method : %s\n,  length of it is %d\n",outL,strlen(outL));
	
	starttime = start_rdtsc();

	
	for(i=0;i<TEST;i++)
		sm4_256_decrypt_lai_massey(outL,outR,outLo,outRo,ks);
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	printf("circles/byte(256) decryption:%llu\n",ans/(TEST*16));
	
	dump_hex(outL,16);
	printf("decrypted data with lai_massey method : %s,  length of it is %d\n",outLo,strlen(outLo));
	
	
	return 0;
}


int main(){//test ecb
	uint8_t key[] = {"1234567890123456abcessdfghajqkwj"}; 
    
	
	uint64_t starttime,endtime,ans;
	SM4_256_KEY *ks = (SM4_256_KEY*)malloc(sizeof(SM4_256_KEY));
	uint8_t plaintext[] = {"1234567890123456abcessdfghajqkwj1234567890123456abcessdfghajqkwj1234567890123456abcessdfghajqkwj1234567890123456abcessdfghajqkwj"};
	uint8_t cyphertext[256];
	uint8_t decrypttext[128] = {0x00};
	//printf("what?\n");
	set_key_lai_massey(key,ks);
	printf("plaintext:%s\n",plaintext);
	//printf("what?\n");

	

	return 0;
	}


int mainasd5(){
	
	
	//strfromf32x(test,32,uint32_t,a);
	char iv[16]={0x21,0x41,0xa1,0x22,0x95,0x96,0x21,0x41,0x31,0x77,0x89,0xab,0xc1,0x66,0x00,0x01}; 
	char iv_d[16]={0x21,0x41,0xa1,0x22,0x95,0x96,0x21,0x41,0x31,0x77,0x89,0xab,0xc1,0x66,0x00,0x01}; 
	char in[64] = {"asdfghjquy12345678901234567890123456789012345678901ioquyshgd1234"};
	unsigned char e_buf[32];
	char out[64];
	char decrypted_out[64];
	char key[32] = {"1234567890123456"};
	printf("original:\n");
	dump_hex(in,64);
	printf("encrypted:\n");
	SM4_KEY *ks;
	ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	sm4_256_set_key_lai_massey(key,ks);
	
	crypto_ctr128_encrypt(in,out,64,key,ks,iv,e_buf,0,2);
	dump_hex(out,64);
	printf("decrypted:\n");
	crypto_ctr128_encrypt(out,decrypted_out,64,key,ks,iv_d,e_buf,0,2);
	dump_hex(decrypted_out,64);
	
	
	
	
	
	
	return 0;
	}
