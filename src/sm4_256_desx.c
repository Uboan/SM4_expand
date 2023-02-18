#include "sm4.h"
#include <string.h>
#include "sm4_256_desx.h"
#include <omp.h>
#define ossl_inline inline
#define CTR_PARALLEL 6
int sm4_256_set_key_desx(const uint8_t *key,SM4_KEY *ks){
	
	return ossl_sm4_set_key(key,ks);
	
	}

void sm4_256_encrypt_desx(uint8_t *in,uint8_t *out,const uint8_t *key,SM4_KEY *ks){

	int len = strlen(in);
	if(len>block_size) len = block_size; //cuz the sm4_128 encryption is for 16 bytes.
	
	uint8_t *in_x = (uint8_t *)calloc(len,sizeof(uint8_t));
	
	int i,j;
	for(i=0;i<len;i++){
		
		in_x[i] = in[i]^key[128+i];
		
		}
	ossl_sm4_encrypt(in_x,out,ks);
	for(i=0;i<len;i++){
		out[i] = out[i]^key[128+i];
		}
	free(in_x);
}

void sm4_256_decrypt_desx(uint8_t *in,uint8_t *out,const uint8_t *key,SM4_KEY *ks){
	
	int len = strlen(in);
	if(len>block_size) len = block_size;
	
	uint8_t *in_x = (uint8_t *)calloc(len,sizeof(uint8_t));
	int i,j;
	for(i=0;i<len;i++){
		
		in_x[i] = in[i]^key[128+i];
		
		}
	ossl_sm4_decrypt(in_x,out,ks);	
	for(i=0;i<len;i++){
		
		out[i] = out[i]^key[128+i];
		
		}
	free(in_x);	
	}

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
void sm4_desx_ctr_set_counter(unsigned char *counter,int set_num){
    uint64_t p;

    //p = load_64_be(counter,1);
    p=set_num;//just for testing, set it to zero everytime 
    store_u128_be(p,counter);

}
    void sm4_desx_ctr_inc(unsigned char *counter)
    {
		 uint64_t p;

		p = load_64_be(counter,1);

		p++;

		store_u128_be(p,counter);
    }

    void sm4_desx_ctr_encrypt(const char *in, char *out, int len, const void *key, SM4_KEY *ks, unsigned char ivec[16], unsigned char ecount_buf[16], unsigned int num, int Cypher)
    {
		    unsigned int n;
		#ifdef CTR_PARALLEL
		{
			omp_set_num_threads(CTR_PARALLEL);
			#pragma omp parallel
			{
			int parallell =CTR_PARALLEL;
			int omp_id = omp_get_thread_num();
			int length = len;
			length -= (16 * omp_id); // if detected the data block has allocated enough processors then it would get in the loop below
			unsigned char iv_p[16];
			unsigned char ecount_buf_p[32];
			uint8_t *out_t = out + omp_id * (16);
			const uint8_t *in_t = (in + omp_id * (16));

			int ind = 0;
			
			/* initialization of variables */
			for (int i = 0; i < 16; i++)
				iv_p[i] = ivec[16];
			ctr128_inc_nstep(iv_p, omp_id);
			while (length >= 16)
			{             
				sm4_256_encrypt_desx(ivec,ecount_buf,key,ks);
				ctr128_inc_nstep(iv_p, parallell);
				for (ind = 0; ind < 16; ind++)
					out_t[ind] = in_t[ind] ^ ecount_buf_p[n];
				length -= 16 * parallell;
				out_t += 16 * parallell;
				in_t += 16 * parallell;
				ind = 0;
			}
					
				
			}
		}

		#else
		{  
			
			int l=0;
			n = num;
			while(len>=16){
						sm4_256_encrypt_desx(ivec,ecount_buf,key,ks);
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
		}
		#endif
	
		return;
    }


    void sm4_desx_cbc_encrypt(uint8_t *in, uint8_t *out, uint8_t *ivec, size_t len, const void *key,SM4_KEY *ks)
    {
		size_t n; 
		uint8_t * out1 = out;
		unsigned char plbuf[16];//输入缓存
		unsigned char ivbuf[16];//异或变量缓存
		unsigned char clbuf[16];//输出缓存
		uint8_t * in1 = in;
		// printf("\n输入明文：");
		// dump_hex(in1, len);
		for (size_t i = 0; i < 16; i++)
		{   //装填初始变量
			ivbuf[i] = ivec[i]; 
		}

		int i = 0;
		while(len >= 16)//分组长度为16byte
		{
			for(n = 0; n < 16; ++n)
			{
				plbuf[n] = in1[n] ^ ivbuf[n];//缓存:明文与初始变量进行异或
			//key everytime
				
			}
			// printf("\n明文异或：");
			// dump_hex(plbufLeft, 16);
			sm4_256_encrypt_desx(plbuf,clbuf,key,ks);
			// printf("\n密文：");
			// dump_hex(clbufLeft, 16);
			// printf("\nR8：");
			// dump_hex(clbufRight, 16);
			for(n = 0; n < 16; ++n)
			{
				out1[n] = clbuf[n]; 
			}
			// printf("\n密文+r8：");
			// dump_hex(out1, 32);
			//一轮完成.........
			for (size_t i = 0; i < 16; i++)
			{
				ivbuf[i] = clbuf[i]; 
			}
			
			// printf("\n加密iv:");
			// dump_hex(iv, 16);
			len -= 16;
			in1 += 16;
			out1 += 16;
		}
		
		if (len > 0){//不足16byte的数据在这里处理，有补全函数可以在这补全
			for (n = 0; n < len; n++)
			{
			out1[n] = in1[n];
			}
			
		}
		//  printf("\nresult:");
		//  dump_hex(out, 65);
    }

    void sm4_desx_cbc_decrypt(uint8_t *in, uint8_t *out, uint8_t *ivec, size_t len,const void *key, SM4_KEY *ks)
    {
		 size_t n; 
		uint8_t * out1 = out;
		unsigned char plbuf[16];//输入缓存
		unsigned char clbuf[16];//输出缓存
		unsigned char ivbuf[16];//异或变量缓存
		uint8_t * in1 = in;
		int i = 0;
		// printf("\n密文：");
		// dump_hex(in1, 65);
		for (size_t i = 0; i < 16; i++)
			{   //装填初始变量
				ivbuf[i] = ivec[i]; 
			}

    while(len >= 16)//分组长度为16byte
    {
        for(n = 0; n < 16; ++n)
        {
           plbuf[n] = in1[n];
            
        }
        sm4_256_decrypt_desx(plbuf,clbuf,key,ks);
        
        // printf("\nkey1:");
        // dump_hex(clbufRight,16);
        // printf("\n明文异或后的值:");
        // dump_hex(clbufLeft,16);
        //  printf("\n异或变量:");
        // dump_hex(iv,16);
        for(n = 0; n < 16; ++n)
        {
           out1[n] = clbuf[n] ^ ivbuf[n];
        }
        
        // printf("\n明文:");
        // dump_hex(out1,16);
        //一轮完成.........
        //iv = plbufLeft;
        for (size_t i = 0; i < 16; i++)//不能直接iv = plbufLeft，这样是修改指针的指向，而plbufLeft的值在循环前部改变了
        {
           ivbuf[i] = plbuf[i];
        }
        
        // printf("\n异或变量（上一次的密文）:");
        // dump_hex(iv,16);
        len -= 16;
        in1 += 16;
        out1 += 16;
    }
    if (len > 0){//不足16byte的数据在这里处理，有补全函数可以在这补全，len指的是明文长度
        for (n = 0; n < len; n++)
        {
           out1[n] = in1[n];
        }
        
    }
    }
