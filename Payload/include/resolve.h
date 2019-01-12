#pragma once

#include "types.h"

void *M_TEMP;

void *(*malloc)(unsigned long size, void *type, int flags);
void (*free)(void *addr, void *type);
void (*memcpy)(void *dst, const void *src, size_t len);
void *(*memset)(void * ptr, int value, size_t num);
int (*memcmp)(const void * ptr1, const void * ptr2, size_t num);
size_t (*strlen)(const char *str);

void resolve(uint64_t kernbase);