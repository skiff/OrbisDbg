#pragma once

#include "types.h"

uint64_t getkernbase();
void *alloc(uint32_t size);
void dealloc(void *addr);
int sys_dynlib_dlsym(int loadedModuleID, const char *name, void *destination);
int sys_dynlib_load_prx(const char *name, int *idDestination);
void resolveImports();

extern int(*sceKernelLoadStartModule)(const char *name, size_t argc, const void *argv, unsigned int flags, int, int);
extern int(*sceSysUtilSendSystemNotificationWithText)(int messageType, const char* message);