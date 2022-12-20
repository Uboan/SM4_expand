/*
 * @Date: 2022-11-02 06:48:08
 * @LastEditors: zyp
 * @LastEditTime: 2022-11-02 07:46:21
 * @FilePath: /sm4_256/test/test_LUT_EM.c
 * @Description: 
 * 
 * Copyright (c) 2022 by CBA511, All Rights Reserved. 
 */
#include <stdio.h>
#include "sm4.h"
#include <stdlib.h>
#include <string.h>
#include "pksc7_padding.h"
#include "util.h"
#include "lut_sm4.h"

#include "lut_sm4_even_mansour.h"

#define TEST 1000000

int main(){// test sm4_256_3des 
	
	uint8_t key1[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t key2[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}; 
		uint8_t in[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	uint8_t out[16] = {0x00},out2[17] = {0x00};  
	
	uint64_t starttime,endtime,ans;
    SM4_Key sm4_key;
    int success = SM4_LUT_EM_KeyInit(key1,&sm4_key);
    if(success){

printf("original data: %s\n",in);
    	dump_hex(in,16);
        //SM4_Encrypt(in,out,sm4_key);
        SM4_LUT_EM_Encrypt(in,out,key2,sm4_key);
        int i;
        
	
    printf("encrypt:\n");
    dump_hex(out,16);
    SM4_LUT_EM_Decrypt(out,out2,key2,sm4_key);
    //SM4_Decrypt(out,out2,sm4_key);
    printf("decrypted:\n");
    dump_hex(out2,16);
	starttime = start_rdtsc();
	
	for(i=0;i<TEST;i++)
		SM4_LUT_EM_Encrypt(in,out,key2,sm4_key);
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	printf("circles/byte(256) encryption:%llu\n",ans/(TEST*16));
	
	
	dump_hex(out,16);
	printf("encrypted data with even_mansour method : %s\n,  length of it is %d\n",out,strlen(out));
	
	starttime = start_rdtsc();
	
	for(i=0;i<TEST;i++)
		SM4_LUT_EM_Decrypt(out,out2,key2,sm4_key);
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	printf("circles/byte(256) decryption:%llu\n",ans/(TEST*16));
	
	dump_hex(out2,16);
	printf("decrypted data with even_mansour method : %s,  length of it is %d\n",out2,strlen(out2));
	

    }

    SM4_LUT_EM_KeyDelete(sm4_key);

	//SM4_Key *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	
	//SM4_LUT_EM_KeyInit(key1,ks);

	
	

	

	
	return 0;
}

// gcc test_even_mansour.c sm4_256_even_mansour.c sm4.c util.c pksc7_padding.c -o test_even_mansour


