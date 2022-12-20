#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(){
	
	FILE *fp = NULL;
	fp = fopen("test_data_16.da","w+");
	
	for(int i=0;i<16;i++){
		fputc('0',fp);
		
		
		}
	fclose(fp);	
	fp = fopen("test_data_64.da","w+");
	
	for(int i=0;i<64;i++){
		fputc('1',fp);
		
		
		}
	fclose(fp);
		fp = fopen("test_data_256.da","w+");
	
	for(int i=0;i<256;i++){
		fputc('2',fp);
		
		
		}
	fclose(fp);
	
	
	fp = fopen("test_data_1024.da","w+");
	
	for(int i=0;i<1024;i++){
		fputc('3',fp);
		
		
		}
	fclose(fp);
	fp = fopen("test_data_8192.da","w+");
	
	for(int i=0;i<8192;i++){
		fputc('4',fp);
		
		
		}
	fclose(fp);	
	fp = fopen("test_data_16384.da","w+");
	
	for(int i=0;i<16384;i++){
		fputc('5',fp);
		
		
		}
	fclose(fp);	
	return 0;
	}
	





