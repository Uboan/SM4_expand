#include "crypto.h"
#include <string.h>

uint8_t iv[32]={"00000000000000000000000000000000"};

int set_key_lai_massey(const uint8_t *key,SM4_256_KEY *ks){
	
	ks->ks128 = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	ks->key = (char*)malloc(256);
	strcpy(ks->key,key);
	
	//ks->key = key;
	return sm4_256_set_key_lai_massey(key,ks->ks128);
	};

int sm4_256_set_key(const uint8_t *key,SM4_256_KEY *ks,int block){
	
	ks->ks128 = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	ks->key = (char*)malloc(256);
	strcpy(ks->key,key);
	
	//ks->key = key;
	if(block==Lai_Massey)
		return sm4_256_set_key_lai_massey(key,ks->ks128);
	else
		return sm4_256_set_key_lai_massey(key,ks->ks128);
	};
	
//uint8_t out_src[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
void crypto_encrypt(uint8_t *in_data,uint8_t *out_data,SM4_256_KEY *ks,int block){
	switch(block){
		case Lai_Massey://only for gcm use 
		{
			uint64_t src[2];
			sm4_256_encrypt_lai_massey(in_data,ks->key+16,out_data,src,ks->ks128);
			return;
		}
		
		case Even_Mansour:
			sm4_256_encrypt_even_mansour(in_data,out_data,ks->key,ks->ks128);
			return;
		case 3://test only gcm mode, just ignore it
		{		
			uint64_t src[2];
			sm4_256_encrypt_lai_massey(in_data,ks->key+16,out_data,src,ks->ks128);
		}
		case 4://sm4-128 gcm
		{
			ossl_sm4_encrypt(in_data, out_data, ks->ks128);
		}
	
	};

}
void crypto_decrypt(uint8_t *in_data,uint8_t *out_data,SM4_256_KEY *ks,int block){
	switch(block){
		case Lai_Massey:
			
			sm4_256_decrypt_lai_massey(in_data,ks->key+16,out_data,out_data+16,ks->ks128);
			return;
		case Even_Mansour:
			sm4_256_decrypt_even_mansour(in_data,out_data,ks->key,ks->ks128);
		}
	
	};;
void lai_massey_encrypt_ecb(const uint8_t *in_data,uint8_t *out_data,SM4_256_KEY *ks){
	
	int length = strlen(in_data)/16;

	uint8_t outL[32] = {0x00}, outR[32] = {0x00}; 
	for(int i=0;i<length;i++){
		
		sm4_256_encrypt_lai_massey(in_data+i*16,ks->key+16,outL,outR,ks->ks128);
		
		strcat(out_data,outL);//append both outL and outR to out_data
		strcat(out_data,outR);

		}

	};

void lai_massey_decrypt_ecb(uint8_t *in_data,uint8_t *out_data,SM4_256_KEY *ks){
	int length = strlen(in_data)/16;
	uint8_t outL[32] = {0x00}, outR[32] = {0x00};  
	uint8_t inL[32]= {0x00}, inR[32] = {0x00};
	
	for(int i=0;i<length;i++){
		
		
		strncpy(inL,in_data+i*16,16);//a very unefficient act(its function is only to load 16 bytes data into the process block)
		strncpy(inR,in_data+(++i)*16,16);//a very unefficient act, which are needed to be substituded
		sm4_256_decrypt_lai_massey(inL,inR,outL,outR,ks->ks128);
		
		strcat(out_data,outL);//append both outL to out_data
		

		}
	
	
	
	
}
	


	
	
	
	
