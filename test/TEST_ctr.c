#include <omp.h>
#include "ctr_sm4_256.h"
#include <stdint.h>
#include "util.h"
#include <time.h>
#include <string.h>
#include <sys/wait.h> 
#define OMP_NUM 1
#define TEST1_DATA_SIZE 128
//#define CTR_PARALLEL 8
#define BILLION 1000000000.0
#define TEST 10000
int mainasd(){
	uint8_t iv[4][16]={
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};
	uint8_t ive[5][16]={
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	
	uint8_t key[32]={
		0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,
		0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};	
	uint8_t in_data[128]={
		"12345678901234561234567890123456123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456"
		};
	
	uint8_t enf_buf[32]={0x00};
	uint8_t out_data[256]={0x00};
	uint8_t dec_data[256] = {0x00};
	
	uint64_t starttime,endtime,ans;
	
	SM4_KEY *ks;
	ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	sm4_256_set_key_lai_massey(key,ks);
	
	int index;

	dump_hex(in_data,TEST1_DATA_SIZE);
	printf("in:%s\n",in_data);
	omp_set_num_threads(OMP_NUM);
	//initial process: to set iv in order to achieve multi-ctr_process
	starttime = start_rdtsc();
	
	#define CTR_PARALLEL 4
	crypto_ctr128_encrypt(in_data,out_data,128,key,ks,iv[0],enf_buf,0,1);
	
	
	endtime = end_rdtsc();
	ans  = endtime - starttime;
	//printf("circles/byte(256) encryption:%llu\n",ans/(TEST*16));
	
	
	printf("out:%s\n",out_data);
    dump_hex(out_data,TEST1_DATA_SIZE);
	
	crypto_ctr128_encrypt(out_data,dec_data,128,key,ks,iv[1],enf_buf,0,1);
	
	
	printf("decrypted:%s\n",dec_data);
	dump_hex(dec_data,TEST1_DATA_SIZE);

	return 0;
	
	
	
	}
void init_test_data(uint8_t *buf,long int amount){
	
	for(int i=0;i<amount;i++){
		buf[i] = '8';
		
		
		}
	
	}
static inline unsigned long long rdtsc(void)  
{  
    unsigned hi, lo;  
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));  
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );  
}  


int maintest(int block){
	uint8_t iv[8][16]={
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};
	uint8_t ive[9][16]={
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	
	uint8_t key[32]={
		0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,
		0x17,0x18,0x22,0x55,0x89,0x03,0x65,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
		};	
	//printf("???");
	uint8_t enf_buf[32]={0x00};
	//uint8_t *out_data;
	//uint8_t *dec_data;
	//uint8_t *in_data;
	
	
	/*time measure variables*/
	uint64_t starttime,endtime,ans;
	clock_t begin,end;
	struct timespec start,stop;
	//uint64_t nanosec;
	//double accum;
	/* end of time measure variables*/
	
	
	
	uint8_t buf[1048576] = {'0'};
	uint8_t out_buf[1048576];
	uint8_t dec_buf[1048576];
	SM4_KEY *ks;
	ks = (SM4_KEY*)malloc(sizeof(SM4_KEY));
	sm4_256_set_key_lai_massey(key,ks);
	FILE *fp =NULL;
	
	uint64_t amount=16;
	int set_omp_num=1;
	
	init_test_data(buf,1048576);
	//int cypher=1;//LM 
	int cypher = block;//1 for KM ,2 for EM, 4 for SM4-128
	char cypher_name[2][16]={"Lai M 256-ctr","Even M 256-ctr"," ","SM4-128"};
	
	if(cypher==1)printf("LM ctr128:\n");
		else printf("EM ctr128:\n");
	
	#if defined CTR_PARALLEL
	amount = CTR_PARALLEL;
	//printf("starting parallel program with %d thread(s) :\n",CTR_PARALLEL-0);
	#endif
		//initial process: to set iv in order to achieve multi-ctr_process
		
	for(amount=16;amount<=1048576;amount*=4){
		
		
		unsigned long long int i=0;
		
	
		time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
	
		start_crypt_time = time(NULL);
		//starttime = start_rdtsc();
		while(time(NULL)<endwait)
		{
			i++;
			crypto_ctr128_encrypt(buf,out_buf,amount,key,ks,iv[0],enf_buf,0,cypher);
			ctr128_set_counter(iv[0],0);
		}
		finish_crypt_time = time(NULL);
	/*
	//clock_gettime(CLOCK_REALTIME,&stop);
	
	//endtime = end_rdtsc();
	//ans  = (endtime - starttime)/(TEST*16);
	
	//ans = endtime-starttime;
	//
	 * */
	 double time_used = (finish_crypt_time - start_crypt_time);
		printf("doing %s for 3s on %d size blocks %lld in %.2fs\n",cypher_name[cypher-1],amount,i,time_used);
		printf("Mbps :%dMbps \n",i*amount/3/1000000);

			starttime = start_rdtsc();
		for(i=0;i<TEST;i++){
			
			crypto_ctr128_encrypt(buf,out_buf,amount,key,ks,iv[0],enf_buf,0,cypher);
			ctr128_set_counter(iv[0],0);
			
			
			
			
		}
			endtime = end_rdtsc();
			ans = endtime - starttime;
		printf("cpu cycles/byte in doing %s on %d size blocks for :%llu \n",cypher_name[cypher-1],amount,ans/TEST/amount);
			
			
			
	
		
		
		
		
	}
	
	
	
	return 0;
	}
	int main(){
		
		maintest(1);
		maintest(2);
		return 0;
	}
	
	