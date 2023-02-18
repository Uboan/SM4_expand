#include <omp.h>
#include "sm4_256_3des.h"
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
	SM4_3des_KEY *ks;
	ks = (SM4_3des_KEY*)malloc(sizeof(SM4_3des_KEY));
	sm4_256_set_key_3des(key,ks);
	FILE *fp =NULL;
	
	uint64_t amount=16;
	int set_omp_num=1;
	
	init_test_data(buf,1048576);
	//int cypher=1;//LM 
	int cypher = block;//1 for SM4-256, 2 for SM4-128
	char cypher_name[2][16]={"SM4-256-3des-ctr","SM4-128-ctr"};
	
	
		
	//for(amount=16;amount<1048576;amount*=4){
		

		amount = 8192;
		unsigned long long int i=0;
		
	
		time_t endwait = time(NULL) + 3,finish_crypt_time,start_crypt_time;
	
		start_crypt_time = time(NULL);
		//starttime = start_rdtsc();
		while(time(NULL)<endwait)
		{
			i++;
			sm4_3des_ctr_encrypt(buf,out_buf,amount,key,ks,iv[0],enf_buf,0,cypher);
			sm4_3des_ctr_set_counter(iv[0],0);
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
		// printf("doing %s for 3s on %d size blocks %lld in %.2fs\n",cypher_name[cypher-1],amount,i,time_used);
		// printf("Mbps :%dMbps \n",i*amount/3/1000000);
		// printf("kbyte/s :%.2f \n",i*amount/time_used/1024);
		printf("%lld ",i);
		printf("%.2f \n",i*amount/time_used/1024);
		// 	starttime = start_rdtsc();
		// for(i=0;i<TEST;i++){
			
		// 	sm4_3des_ctr_encrypt(buf,out_buf,amount,key,ks,iv[0],enf_buf,0,cypher);
		// 	sm4_3des_ctr_set_counter(iv[0],0);
			
			
			
			
		// }
		// 	endtime = end_rdtsc();
		// 	ans = endtime - starttime;
		// printf("cpu cycles/byte in doing %s on %d size blocks for :%llu \n",cypher_name[cypher-1],amount,ans/TEST/amount);
		
			
			
	
		
		
		
		
	//}
	
	
	free(ks);
	return 0;
	}
	int main(){
		
		maintest(1);
		
		return 0;
	}
	