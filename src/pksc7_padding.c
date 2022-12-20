#include <string.h>
#include"pksc7_padding.h"

uint8_t pad_byte[]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
uint8_t padding_byte[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};


uint8_t* pksc7_padding(const uint8_t *in){//*out should be NULL
	int len = strlen(in),i;
	int padding_len =(block_size - len%block_size)%block_size;
	uint8_t *out;
	out = (uint8_t *)calloc(len+padding_len,sizeof(uint8_t));
	if(out == NULL){
		return NULL;
		}
	strncpy(out,in,len);
	//free(in);

	if(padding_len == 0)
		for(i=0;i<block_size;i++)
			out[len+i] = padding_byte[0];
	for(i=0;i<padding_len;i++)
		out[len+i] = padding_byte[padding_len];

	return out;
	

}
#if 0
int pksc7_stripping(uint8_t *in){
	int len = strlen(in);
	int padding_len = (int)(in[len-1]-'0');
	in[len-padding_len] = '\0';
	return 1;
	
	
	
}
#endif

uint8_t *pksc7_stripping(uint8_t *in){
	int len = strlen(in),i;
	int padding_len = (int)(in[len-1]-'0');
	uint8_t *out;
	out = (uint8_t *)calloc(len,sizeof(uint8_t));
	strcpy(out,in);
	out[len-padding_len] = '\0';
	return out;
	
	}	
	
