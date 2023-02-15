#include"sm4_expand.h"
#include"sm4_256_3des.h"
#include"sm4_256_desx.h"
#include"util.h"
#include"stdlib.h"
#include <time.h>
#define TEST_CASE_SIZE 1024
#define KEY_ARRAY_SIZE 1024

void rand_uint8_n(uint8_t *data,int n){
    if(data==NULL)
        return;
    int r=rand()%256;

    for(int i=0;i<n;i++){
        r=(rand()+i)%256;
        data[i] = 0x00+r;
    }
}

int Is_equal(uint8_t *data1,uint8_t *data2,int n){//equal:return 1
    for(int i=0;i<n;i++){
        if(data1[i]!=data2[i])
            return 0;
    }
    return 1;
}

int test_correctness(){

    uint8_t dt_key[KEY_ARRAY_SIZE][32];//随机生成 1024组256 bit密钥
    SM4_EXPAND_KEY *ks;
    int count=0;
    for(int i=0;i<KEY_ARRAY_SIZE;i++)
        rand_uint8_n(dt_key[i],32);
    
    uint8_t dt_plaintext[TEST_CASE_SIZE][16];//随机生成的 1024组明文
    uint8_t dt_ciphertext[TEST_CASE_SIZE][16];
    uint8_t dt_decryptedtext[TEST_CASE_SIZE][16];
    for(int i=0;i<TEST_CASE_SIZE;i++)
        rand_uint8_n(dt_plaintext[i],16);

    ks = (SM4_EXPAND_KEY*)malloc(sizeof(SM4_EXPAND_KEY));//先分配空间，然后再set key

    for(int i=0;i<KEY_ARRAY_SIZE;i++){

        sm4_expand_set_key(dt_key[i],ks);
        if(count<10){
                printf("key:");
                dump_hex(dt_key[i],32);
            }
        for(int j=0;j<TEST_CASE_SIZE;j++){
            sm4_expand_encrypt(dt_plaintext[j],dt_ciphertext[j],ks);
            sm4_expand_decrypt(dt_ciphertext[j],dt_decryptedtext[j],ks);
            if(count++<10){
                printf("plaintext:");
                dump_hex(dt_plaintext[j],16);
                printf("ciphertext:");
                dump_hex(dt_ciphertext[j],16);
                printf("decrypted text:");
                dump_hex(dt_decryptedtext[j],16);
            }
            if(Is_equal(dt_plaintext[j],dt_decryptedtext[j],16)!=1){
                free(ks);
                return 0;
            }
                
        }
    }
    //printf(dt);
    return 1;
}
#define TEST 100000
int scheme_cp_test(){//方案对比测试：SM4-128，SM4-256-3DES，SM4-256-DESX，SM4-expand

    uint8_t *key={"12345678901234567890123456789012"};//256 bit 主密钥
    uint8_t data[16]={"1234567890123456"};
    uint8_t data_encrypted[17];
    uint8_t data_decrypted[17];
    uint64_t starttime,endtime,ans;
    int i;
    //SM4-128:
    SM4_KEY *ks_128;
    ks_128 = (SM4_KEY*)malloc(sizeof(SM4_KEY));
    ossl_sm4_set_key(key,ks_128);
    starttime = start_rdtsc();
		for(i=0;i<TEST;i++){	
			ossl_sm4_encrypt(data,data_encrypted,ks_128);
		
		}
	endtime = end_rdtsc();
	ans = endtime - starttime;
    time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        ossl_sm4_encrypt(data,data_encrypted,ks_128);
    }
    finish_crypt_time = time(NULL);

    printf("doing SM4-128 for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
	printf("cpu cycles/byte in doing %s on %d size blocks for :%llu \n\n","SM4-128",16,ans/TEST/16);
			
    //SM4-256-3des:
    SM4_3des_KEY *ks_3des;
    ks_3des = (SM4_3des_KEY*)malloc(sizeof(SM4_3des_KEY));
    sm4_256_set_key_3des(key,ks_3des);
   
	starttime = start_rdtsc();
		for(i=0;i<TEST;i++){	
			sm4_256_encrypt_3des(data,data_encrypted,ks_3des);
		
		}
	endtime = end_rdtsc();

	ans = endtime - starttime;
    endwait = time(NULL) + 3;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        sm4_256_encrypt_3des(data,data_encrypted,ks_3des);
    }
    finish_crypt_time = time(NULL);

    printf("doing 3des for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
    printf("cpu cycles/byte in doing %s on %d size blocks for :%llu \n\n","SM4-256-3des",16,ans/TEST/16);
			
	//SM4-256-desx:
    SM4_KEY *ks_desx;
    ks_desx =(SM4_KEY*)malloc(sizeof(SM4_KEY));
    sm4_256_set_key_desx(key,ks_desx);	
    
    starttime = start_rdtsc();
		for(i=0;i<TEST;i++){	
			sm4_256_encrypt_desx(data,data_encrypted,key+16,ks_desx);
		
		}
	endtime = end_rdtsc();
	ans = endtime - starttime;

    endwait = time(NULL) + 3;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        sm4_256_encrypt_desx(data,data_encrypted,key+16,ks_desx);
    }
    finish_crypt_time = time(NULL);

    printf("doing desx for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
	printf("cpu cycles/byte in doing %s on %d size blocks for :%llu \n\n","SM4-256-desx",16,ans/TEST/16);

    //SM4-expand
    SM4_EXPAND_KEY *ks;
    ks = (SM4_EXPAND_KEY*)malloc(sizeof(SM4_EXPAND_KEY));//先分配空间，然后再set key
    sm4_expand_set_key(key,ks);

    starttime = start_rdtsc();
		for(i=0;i<TEST;i++){	
			sm4_expand_encrypt(data,data_encrypted,ks);
		
		}
	endtime = end_rdtsc();
	ans = endtime - starttime;

   endwait = time(NULL) + 3;
    start_crypt_time = time(NULL);
    while(time(NULL)<endwait)
    {
        i++;
        sm4_expand_encrypt(data,data_encrypted,ks);
    }
    finish_crypt_time = time(NULL);

    printf("doing SM4-Expand for 3s on %d size blocks %lld in %.2fs\t",16,i,(double)(finish_crypt_time - start_crypt_time));
    printf("%.2fMbps\n",(double)(i*16/1000000));//million bit
		


	printf("cpu cycles/byte in doing %s on %d size blocks for :%llu \n\n","SM4-256-expand",16,ans/TEST/16);
		
    

    return 1;
}

int main(){
     #if 0
    uint8_t *key={"12345678901234567890123456789012"};//256 bit 主密钥
    SM4_EXPAND_KEY *ks;
    ks = (SM4_EXPAND_KEY*)malloc(sizeof(SM4_EXPAND_KEY));//先分配空间，然后再set key
    sm4_expand_set_key(key,ks);
    uint8_t data[16]={"1234567890123456"};
    uint8_t data_encrypted[17];
    uint8_t data_decrypted[17];
    
    printf("original data:\n");
    dump_hex(data,16);
    sm4_expand_encrypt(data,data_encrypted,ks);
    printf("encrypted data:\n");
    dump_hex(data_encrypted,16);
    
    sm4_expand_decrypt(data_encrypted,data_decrypted,ks);
    printf("decrypted data:\n");
    dump_hex(data_decrypted,16);
    #endif

    if(test_correctness()==1)
        printf("----Correctness Test----\n for %d keys,and for %d plaintexts passed!\n\n",KEY_ARRAY_SIZE,TEST_CASE_SIZE);

    scheme_cp_test();
    return 0;
}

