#include "main.h"

struct payloadArgs {
	uint64_t sycall;
	void *payload;
	size_t psize;
};

extern uint8_t OrbisDbgElf[];
extern int32_t OrbisDbgElfSize;

int install_payload(struct thread *td, uint64_t kernbase, void *payload, size_t psize) {
	vm_offset_t (*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)(kernbase + __kmem_alloc);
	vm_map_t kernel_map = *(vm_map_t *)(kernbase + __kernel_map);

	size_t msize = 0;
	if (elf_mapped_size(payload, &msize)) {
		return 1;
	}

	int s = (msize + 0x3FFFull) & ~0x3FFFull;
	void *payloadbase = (void*)kmem_alloc(kernel_map, s);
	if (!payloadbase) {
		return 1;
	}

	int r = 0;
	int (*payload_entry)(void *p);

	if ((r = load_elf(payload, psize, payloadbase, msize, (void **)&payload_entry))) {
		return r;
	}

	if (payload_entry(NULL)) {
		return 1;
	}

	return 0;
}

void jailbreak(struct thread *td, uint64_t kernbase) {
	void **prison0 =   (void **)(kernbase + __prison0);
	void **rootvnode = (void **)(kernbase + __rootvnode);

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *prison0;
	fd->fd_rdir = fd->fd_jdir = *rootvnode;
}

int kernelPayload(struct thread *td, struct payloadArgs *args) {
	uint64_t kernbase = getkernbase();
	resolve(kernbase);

	uint64_t CR0 = __readcr0();
	__writecr0(CR0 & ~CR0_WP);

	jailbreak(td, kernbase);

	uint8_t *disable_console_output = (uint8_t*)(kernbase + __disable_console_output);
	*disable_console_output = 0;

    *(uint8_t*)(kernbase + 0x1EA53D) = 0xEB;
    *(uint8_t*)(kernbase + 0x30D9AA) = 0xEB;
    *(uint16_t*)(kernbase + 0x194875) = 0x9090;
    *(uint8_t*)(kernbase + 0xFCD48) = VM_PROT_ALL;
    *(uint8_t*)(kernbase + 0xFCD56) = VM_PROT_ALL;

    memcpy((void*)(kernbase + 0x11730), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);
    memcpy((void*)(kernbase + 0x117B0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);
    memcpy((void*)(kernbase + 0x117C0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);
    memcpy((void*)(kernbase + 0x13F03F), "\x31\xC0\x90\x90\x90", 5);
    memcpy((void*)(kernbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);
    memcpy((void*)(kernbase + 0x30DE01), "\xE9\xD0\x00\x00\x00", 5);

	__writecr0(CR0);

    return install_payload(td, kernbase, args->payload, args->psize);
}

int _main(void) {
	syscall(11, kernelPayload, OrbisDbgElf, OrbisDbgElfSize);

	resolveImports();
    sceSysUtilSendSystemNotificationWithText(222, "OrbisDbg Loaded");
	return 0;
}