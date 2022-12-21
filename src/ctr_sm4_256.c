#include "ctr_sm4_256.h"
#include "string.h"
#include <omp.h>
#define ossl_inline inline
#define CTR_PARALLEL 4
static ossl_inline uint64_t load_64_be(const uint8_t*b,uint32_t n){//load n_th elements of 64 block in b array to become  a real uint64_t
	return ((uint64_t)b[8*n]<<56)|
		   ((uint64_t)b[8*n+1]<<48)|
		   ((uint64_t)b[8*n+2]<<40)|
		   ((uint64_t)b[8*n+3]<<32)|
		   ((uint64_t)b[8*n+4]<<24)|
		   ((uint64_t)b[8*n+5]<<16)|
		   ((uint64_t)b[8*n+6]<<8)|
		   ((uint64_t)b[8*n+7]);
	
	
	}
static ossl_inline void store_u64_be(uint64_t v,uint8_t *b){
	b[0] = (uint8_t)(v>>56);
	b[1] = (uint8_t)(v>>48);
	b[2] = (uint8_t)(v>>40);
	b[3] = (uint8_t)(v>>32);
	b[4] = (uint8_t)(v>>24);
	b[5] = (uint8_t)(v>>16);
	b[6] = (uint8_t)(v>>8);
	b[7] = (uint8_t)(v);
	}
static ossl_inline void store_u128_be(uint64_t v,uint8_t *b){


	//dump_hex(b,16);
	
	b[8] = (uint8_t)(v>>56);
	b[9] = (uint8_t)(v>>48);
	b[10] = (uint8_t)(v>>40);
	b[11] = (uint8_t)(v>>32);
	b[12] = (uint8_t)(v>>24);
	b[13] = (uint8_t)(v>>16);
	b[14] = (uint8_t)(v>>8);
	b[15] = (uint8_t)(v);
	}

void ctr128_inc(unsigned char *counter){//the counter should be endian
	
	uint64_t p;

	p = load_64_be(counter,1);
	
	
	
	p++;
	
	store_u128_be(p,counter);
	
	//dump_hex(counter,16);
	
	
	
	}
void ctr128_set_counter(unsigned char *counter,int set_num){
	uint64_t p;

	//p = load_64_be(counter,1);
	p=set_num;//just for testing, set it to zero everytime 
	store_u128_be(p,counter);
	
	}
void ctr128_inc_nstep(unsigned char *counter,int step){//the counter should be endian
	
	uint64_t p;

	p = load_64_be(counter,1);
	p+=step;
	
	store_u128_be(p,counter);
	
	//dump_hex(counter,16);
	
	
	
	}
	
	
void crypto_ctr128_setKey(const void *key,SM4_EXPAND_KEY *ks){
	ks = (SM4_EXPAND_KEY*)malloc(sizeof(SM4_EXPAND_KEY));
	sm4_expand_set_key(key,ks);
	
	}
	
void crypto_ctr128_encrypt(const char *in,char *out,
							int len,const void *key,SM4_EXPAND_KEY *ks,
							unsigned char ivec[16],unsigned char ecount_buf[16],
							unsigned int num,int Cypher){
	unsigned int n;
	int l=0;
	n = num;
	while(len>=16){
				sm4_expand_encrypt(ivec,ecount_buf,ks);
				
				//dump_hex(ivec,16);
				ctr128_inc(ivec);
				
				//dump_hex(ecount_buf,16);
				for(n=0;n<16;n++)
					out[n] = in[n]^ecount_buf[n];
				//dump_hex(ecount_buf,32);
				len-=16;
				out+=16;
				in+=16;
				n=0;
				
				
			}	
			
	
	
	
	num = n;
	return;
	}

