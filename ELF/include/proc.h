#ifndef _PROC_H
#define _PROC_H

#include "main.h"

struct proc_vm_map_entry {
	char name[32];
	vm_offset_t start;
	vm_offset_t end;
	vm_offset_t offset;
	uint16_t prot;
};
uint64_t proc_alloc_size(uint64_t p);
int get_proc_count();
struct proc *proc_find_by_name(const char *name);
struct proc *proc_find_by_pid(int pid);
int proc_get_vm_map(struct proc *p, struct proc_vm_map_entry **entries, size_t *num_entries);

int proc_rw_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n, int write);
int proc_read_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n);
int proc_write_mem(struct proc *p, void *ptr, size_t size, void *data, size_t *n);
int proc_allocate(struct proc*p, void **address, size_t size);
int proc_deallocate(struct proc *p, void *address, size_t size);
int proc_mprotect(struct proc *p, void *address, void *end, int new_prot);

#endif
