#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include "sm4_cbc.h"
#include "util.h"
#include <time.h>
#define TEST 10000
#define  NUMBER  1048577
void init_test_data(uint8_t *buf,long int amount){
	int i=0;
	for(;i<amount;i++){
		buf[i] = '8';
		
		
		}
	buf[i] = 0x00;
}
int main(){

    //  uint8_t plaintext[] = {0x89, 0x15, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    //                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    //                         0x23, 0x73, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    //                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
     uint8_t plaintext[NUMBER];
     uint8_t out[NUMBER]; 
     uint8_t out1[NUMBER]; 
     uint8_t *input = plaintext;
     uint8_t *output = out; 
     uint8_t *output1 = out1;   
     uint8_t key1[16] = {
          0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a
     };

     uint8_t ivec[16] = {
          0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
     };
   
     SM4_KEY *ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
     uint64_t starttime,endtime,amount,ans;
     init_test_data(plaintext,1048577);
     sm4_cbc_set_key(key1,ks);
	for(amount=16;amount<=1048576;amount*=4){
		
	
		
		
		uint64_t i=0;
	
		time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
	
		start_crypt_time = time(NULL);
		//starttime = start_rdtsc();
		while(time(NULL)<endwait)
		{
			i++;
			 
			sm4_cbc_decrypt(input,output,ivec,amount,ks);
		}
		finish_crypt_time = time(NULL);

		printf("doing  for 3s on %d size blocks %lld in %.2fs\t",amount,i,(double)(finish_crypt_time - start_crypt_time));
		printf("%.2fMbps\n",(double)(i*amount/1000000));//million bit
	
		
		starttime = start_rdtsc();
		for(i=0;i<TEST;i++){
			sm4_cbc_encrypt(input,output,ivec,amount,ks);
			}
		endtime = end_rdtsc();
		ans = endtime - starttime;
		printf("cpu cycles/byte on %d size blocks for :%llu \n",amount,ans/amount/TEST);
		
	
		
	}	
	

     free(ks);
     return 0;
}