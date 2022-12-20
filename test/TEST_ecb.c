#include <stdio.h>
#include "sm4.h"
#include <stdlib.h>
#include <string.h>
#include "sm4_256_desx.h"
#include "sm4_256_3des.h"
#include "sm4_256_even_mansour.h"
#include "sm4_256_lai_massey.h"
#include "util.h"
#include <time.h>
#include "sm4_expand.h"
#define TEST 1000000
uint8_t key128[16] = {
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a
    };
uint8_t key256[32] = {
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a
    };
uint8_t plaintext[] = {0x89, 0x15, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                            0x23, 0x73, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

int test_3des(){// test sm4_256_3des 
	
	uint64_t starttime,endtime,ans;
	SM4_3des_KEY *ks = (SM4_3des_KEY*)malloc(sizeof(SM4_3des_KEY));;
	sm4_256_set_key_3des(key256,ks);
    uint8_t out[16]; 
    uint8_t out1[16]; 
    uint8_t *input = plaintext;
    uint8_t *output = out; 
    uint8_t *output1 = out1;   
    uint8_t ivec[16] = {
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    uint64_t i=0;
    
    starttime = start_rdtsc();
    for(i=0;i<TEST;i++){
        sm4_256_encrypt_3des(input,output,ks);
        }
    endtime = end_rdtsc();
    ans = endtime - starttime;
    printf("cpu cycles/byte for sm4_256_3des:%llu \n",ans/TEST/16);
    
    time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        sm4_256_encrypt_3des(input,output,ks);
    }
    finish_crypt_time = time(NULL);

    printf("doing 3des for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
    	
    free(ks);
	return 0;
	}
int test_desx(){// test sm4_256_desx 

	SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	uint64_t starttime,endtime,ans;
	sm4_256_set_key_desx(key256,ks);
    uint8_t out[16]; 
    uint8_t out1[16]; 
    uint8_t *input = plaintext;
    uint8_t *output = out; 
    uint8_t *output1 = out1;   
    uint8_t ivec[16] = {
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    uint64_t i=0;
    
    starttime = start_rdtsc();
    for(i=0;i<TEST;i++){
        sm4_256_encrypt_desx(input,output,key256,ks);
    }
    endtime = end_rdtsc();
    ans = endtime - starttime;
    printf("cpu cycles/byte for sm4_256_desx:%llu \n",ans/TEST/16);
    
    time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        sm4_256_encrypt_desx(input,output,key256,ks);
    }
    finish_crypt_time = time(NULL);

    printf("doing desx for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
    
    free(ks);
	return 0;

}
int test_sm4_128(){
    uint8_t out[16]; 
    uint8_t out1[16]; 
    uint8_t *input = plaintext;
    uint8_t *output = out; 
    uint8_t *output1 = out1;   
    uint8_t ivec[16] = {
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
    uint64_t starttime,endtime,ans;
    ossl_sm4_set_key(key128,ks);
    uint64_t i=0;
    starttime = start_rdtsc();
    for(i=0;i<TEST;i++){
        ossl_sm4_encrypt(input,output,ks);
        }
    endtime = end_rdtsc();
    ans = endtime - starttime;
    printf("cpu cycles/byte for sm4_128:%llu \n",ans/TEST/16);
    time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        ossl_sm4_encrypt(input,output,ks);
    }
    finish_crypt_time = time(NULL);

    printf("doing sm4-128 for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
    free(ks);
    return 0;
}

int test_EM(){// test sm4_em
	
	uint8_t out[16]; 
    uint8_t out1[16]; 
    uint8_t *input = plaintext;
    uint8_t *output = out; 
    uint8_t *output1 = out1;   
    uint8_t ivec[16] = {
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
    sm4_256_set_key_even_mansour(key128,ks);
    uint64_t starttime,endtime,ans;
    uint64_t i=0;
    starttime = start_rdtsc();
    for(i=0;i<TEST;i++){
       sm4_256_encrypt_even_mansour(input,output,key128,ks);
    }
    endtime = end_rdtsc();
    ans = endtime - starttime;
    printf("cpu cycles/byte for EM:%llu \n",ans/TEST/16);
    time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        sm4_256_encrypt_even_mansour(input,output,key128,ks);
    }
    finish_crypt_time = time(NULL);

    printf("doing EM for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
    free(ks);
   
	return 0;
}
int test_LM(){// test lai_massey
	
	uint8_t out[16]; 
    uint8_t out1[16]; 
    uint8_t *input = plaintext;
    uint8_t *output = out; 
    uint8_t *output1 = out1;   
    uint8_t ivec[16] = {
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
    sm4_256_set_key_lai_massey(key128,ks);
    uint64_t starttime,endtime,ans;
    uint64_t i=0;
    starttime = start_rdtsc();
    for(i=0;i<TEST;i++){
       sm4_256_encrypt_lai_massey(input,key128,output,output1,ks);
    }
    endtime = end_rdtsc();
    ans = endtime - starttime;
    printf("cpu cycles/byte for LM:%llu \n",ans/TEST/16);
     time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        sm4_256_encrypt_lai_massey(input,key128,output,output1,ks);
    }
    finish_crypt_time = time(NULL);

    printf("doing LM for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
    free(ks);

	return 0;
}
int test_EX(){// test lai_massey
	
	uint8_t out[16]; 
    uint8_t out1[16]; 
    uint8_t *input = plaintext;
    uint8_t *output = out; 
    uint8_t *output1 = out1;   
    uint8_t ivec[16] = {
        0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    SM4_EXPAND_KEY *ks = (SM4_EXPAND_KEY*)malloc(sizeof(SM4_EXPAND_KEY));
    //sm4_256_set_key_lai_massey(key128,ks);
    sm4_expand_set_key(key256,ks);
    uint64_t starttime,endtime,ans;
    uint64_t i=0;
    starttime = start_rdtsc();
    for(i=0;i<TEST;i++){
        sm4_expand_encrypt(input,output,ks);
       //sm4_256_encrypt_lai_massey(input,key128,output,output1,ks);
    }
    endtime = end_rdtsc();
    ans = endtime - starttime;
    printf("cpu cycles/byte for LM:%llu \n",ans/TEST/16);
     time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
       sm4_expand_encrypt(input,output,ks);
    }
    finish_crypt_time = time(NULL);

    printf("doing SM4 expanded for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
    free(ks);

	return 0;
}
int main(){
    test_3des();
    test_desx();
    test_sm4_128();
    test_EM();  
    test_LM();
    test_EX();
    return 0;
}