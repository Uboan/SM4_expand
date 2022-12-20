#pragma once
#include <stdint.h>
#define block_size 16

extern uint8_t pad_byte[];
extern uint8_t padding_byte[];

uint8_t* pksc7_padding(const uint8_t *in);
uint8_t *pksc7_stripping(uint8_t *in);
