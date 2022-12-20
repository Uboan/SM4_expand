/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-06-02 21:23:54
 * @LastEditTime : 2022-06-13 11:42:48
 * @FilePath     : \sm4_256_desx\util.h
 */
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
uint64_t start_rdtsc();
uint64_t end_rdtsc();
void dump_hex(uint8_t * h, int len);
