#include "../include/main.h"

#define RPCSTUB_MAGIC 0x42545352

struct rpcstub_header {
    uint32_t magic;
    uint64_t entry;
    uint64_t rpc_rip;
    uint64_t rpc_rdi;
    uint64_t rpc_rsi;
    uint64_t rpc_rdx;
    uint64_t rpc_rcx;
    uint64_t rpc_r8;
    uint64_t rpc_r9;
    uint64_t rpc_rax;
    uint8_t rpc_go;
    uint8_t rpc_done;
} __attribute__((packed));

#define RPCLDR_MAGIC 0x52444C52

struct rpcldr_header {
    uint32_t magic;
    uint64_t entry;
    uint8_t ldrdone;
    uint64_t stubentry;
    uint64_t scePthreadAttrInit;
    uint64_t scePthreadAttrSetstacksize;
    uint64_t scePthreadCreate;
    uint64_t thr_initial;
} __attribute__((packed));

static const uint8_t rpcstub[410] = {
    0x52, 0x53, 0x54, 0x42, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6C, 0x69, 0x62, 0x6B, 0x65, 0x72,
    0x6E, 0x65, 0x6C, 0x2E, 0x73, 0x70, 0x72, 0x78, 0x00, 0x6C, 0x69, 0x62,
    0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x5F, 0x77, 0x65, 0x62, 0x2E, 0x73,
    0x70, 0x72, 0x78, 0x00, 0x6C, 0x69, 0x62, 0x6B, 0x65, 0x72, 0x6E, 0x65,
    0x6C, 0x5F, 0x73, 0x79, 0x73, 0x2E, 0x73, 0x70, 0x72, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x63, 0x65, 0x4B, 0x65,
    0x72, 0x6E, 0x65, 0x6C, 0x55, 0x73, 0x6C, 0x65, 0x65, 0x70, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x15, 0xD4, 0xFF, 0xFF, 0xFF, 0xBE, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x3D, 0x93, 0xFF, 0xFF, 0xFF, 0xE8, 0xC4, 0x00, 0x00, 0x00,
    0x48, 0x85, 0xC0, 0x74, 0x3F, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D,
    0x15, 0xB2, 0xFF, 0xFF, 0xFF, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D,
    0x3D, 0x80, 0xFF, 0xFF, 0xFF, 0xE8, 0xA2, 0x00, 0x00, 0x00, 0x48, 0x85,
    0xC0, 0x74, 0x1D, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x90,
    0xFF, 0xFF, 0xFF, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x3D, 0x71,
    0xFF, 0xFF, 0xFF, 0xE8, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x90,
    0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x35, 0x79, 0xFF, 0xFF, 0xFF, 0x48, 0x8B,
    0x3D, 0x6A, 0xFF, 0xFF, 0xFF, 0xE8, 0x71, 0x00, 0x00, 0x00, 0x80, 0x3D,
    0x27, 0xFF, 0xFF, 0xFF, 0x00, 0x74, 0x49, 0x4C, 0x8B, 0x0D, 0x0E, 0xFF,
    0xFF, 0xFF, 0x4C, 0x8B, 0x05, 0xFF, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x0D,
    0xF0, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x15, 0xE1, 0xFE, 0xFF, 0xFF, 0x48,
    0x8B, 0x35, 0xD2, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x3D, 0xC3, 0xFE, 0xFF,
    0xFF, 0x4C, 0x8B, 0x25, 0xB4, 0xFE, 0xFF, 0xFF, 0x41, 0xFF, 0xD4, 0x48,
    0x89, 0x05, 0xE2, 0xFE, 0xFF, 0xFF, 0xC6, 0x05, 0xE3, 0xFE, 0xFF, 0xFF,
    0x00, 0xC6, 0x05, 0xDD, 0xFE, 0xFF, 0xFF, 0x01, 0xBF, 0xA0, 0x86, 0x01,
    0x00, 0x4C, 0x8B, 0x25, 0x1F, 0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xD4, 0xEB,
    0x9D, 0x31, 0xC0, 0xC3, 0xB8, 0x52, 0x02, 0x00, 0x00, 0x49, 0x89, 0xCA,
    0x0F, 0x05, 0xC3, 0xB8, 0x4F, 0x02, 0x00, 0x00, 0x49, 0x89, 0xCA, 0x0F,
    0x05, 0xC3
};

static const uint8_t rpcldr[255] = {
    0x52, 0x4C, 0x44, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x70, 0x63,
    0x73, 0x74, 0x75, 0x62, 0x00, 0x48, 0x8B, 0x3D, 0xD9, 0xFF, 0xFF, 0xFF,
    0x48, 0x8B, 0x37, 0x48, 0x8B, 0xBE, 0xE0, 0x01, 0x00, 0x00, 0xE8, 0x7A,
    0x00, 0x00, 0x00, 0x48, 0x8D, 0x3D, 0xD3, 0xFF, 0xFF, 0xFF, 0x4C, 0x8B,
    0x25, 0xA4, 0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xD4, 0xBE, 0x00, 0x00, 0x08,
    0x00, 0x48, 0x8D, 0x3D, 0xBD, 0xFF, 0xFF, 0xFF, 0x4C, 0x8B, 0x25, 0x96,
    0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xD4, 0x4C, 0x8D, 0x05, 0xB4, 0xFF, 0xFF,
    0xFF, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x15, 0x70, 0xFF, 0xFF,
    0xFF, 0x48, 0x8D, 0x35, 0x99, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x3D, 0x8A,
    0xFF, 0xFF, 0xFF, 0x4C, 0x8B, 0x25, 0x73, 0xFF, 0xFF, 0xFF, 0x41, 0xFF,
    0xD4, 0xC6, 0x05, 0x50, 0xFF, 0xFF, 0xFF, 0x01, 0xBF, 0x00, 0x00, 0x00,
    0x00, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0xAF, 0x01, 0x00, 0x00,
    0x49, 0x89, 0xCA, 0x0F, 0x05, 0xC3, 0xB8, 0xA5, 0x00, 0x00, 0x00, 0x49,
    0x89, 0xCA, 0x0F, 0x05, 0xC3, 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83,
    0xEC, 0x18, 0x48, 0x89, 0x7D, 0xE8, 0x48, 0x8D, 0x75, 0xE8, 0xBF, 0x81,
    0x00, 0x00, 0x00, 0xE8, 0xDA, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xC4, 0x18,
    0x5B, 0x5D, 0xC3
};

int proc_create_thread(struct proc *p, uint64_t address) {
    void *rpcldraddr = NULL;
    void *stackaddr = NULL;
    struct proc_vm_map_entry *entries = NULL;
    uint64_t num_entries = 0;
    uint64_t n = 0;
    int r = 0;

    uint64_t ldrsize = sizeof(rpcldr);
    ldrsize += (PAGE_SIZE - (ldrsize % PAGE_SIZE));
    
    uint64_t stacksize = 0x80000;

    r = proc_allocate(p, &rpcldraddr, ldrsize);
    if (r) {
        goto error;
    }

    r = proc_allocate(p, &stackaddr, stacksize);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr, sizeof(rpcldr), (void *)rpcldr, &n);
    if (r) {
        goto error;
    }

    struct thread *thr = TAILQ_FIRST(&p->p_threads);

    r = proc_get_vm_map(p, &entries, &num_entries);
    if (r) {
        goto error;
    }

    uint64_t _scePthreadAttrInit = 0, _scePthreadAttrSetstacksize = 0, _scePthreadCreate = 0, _thr_initial = 0;
    for (int i = 0; i < num_entries; i++) {
        if (entries[i].prot != (PROT_READ | PROT_EXEC)) {
            continue;
        }

        if (!memcmp(entries[i].name, "libkernel.sprx", 14)) {
            _scePthreadAttrInit = entries[i].start + 0x12660;
            _scePthreadAttrSetstacksize = entries[i].start + 0x12680;
            _scePthreadCreate = entries[i].start + 0x12AA0;
            _thr_initial = entries[i].start + 0x84C20;
            break;
        }
        if (!memcmp(entries[i].name, "libkernel_web.sprx", 18))
        {
            _scePthreadAttrInit = entries[i].start + 0x1E730;
            _scePthreadAttrSetstacksize = entries[i].start + 0xFA80;
            _scePthreadCreate = entries[i].start + 0x98C0;
            _thr_initial = entries[i].start + 0x84C20;
            break;
        }
        if (!memcmp(entries[i].name, "libkernel_sys.sprx", 18)) {
            _scePthreadAttrInit = entries[i].start + 0x13190;
            _scePthreadAttrSetstacksize = entries[i].start + 0x131B0;
            _scePthreadCreate = entries[i].start + 0x135D0;
            _thr_initial = entries[i].start + 0x89030;
            break;
        }
    }

    if (!_scePthreadAttrInit) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, stubentry), sizeof(address), (void *)&address, &n);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrInit), sizeof(_scePthreadAttrInit), (void *)&_scePthreadAttrInit, &n);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadAttrSetstacksize), sizeof(_scePthreadAttrSetstacksize), (void *)&_scePthreadAttrSetstacksize, &n);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, scePthreadCreate), sizeof(_scePthreadCreate), (void *)&_scePthreadCreate, &n);
    if (r) {
        goto error;
    }

    r = proc_write_mem(p, rpcldraddr + offsetof(struct rpcldr_header, thr_initial), sizeof(_thr_initial), (void *)&_thr_initial, &n);
    if (r) {
        goto error;
    }

    uint64_t ldrentryaddr = (uint64_t)rpcldraddr + *(uint64_t *)(rpcldr + 4);
    r = create_thread(thr, NULL, (void *)ldrentryaddr, NULL, stackaddr, stacksize, NULL, NULL, NULL, 0, NULL);
    if (r) {
        goto error;
    }

    uint8_t ldrdone = 0;
    while (!ldrdone) {
        r = proc_read_mem(p, (void *)(rpcldraddr + offsetof(struct rpcldr_header, ldrdone)), sizeof(ldrdone), &ldrdone, &n);
        if (r) {
            goto error;
        }
    }

error:
    if (entries) {
        free(entries, M_TEMP);
    }

    if (rpcldraddr) {
        proc_deallocate(p, rpcldraddr, ldrsize);
    }

    if (stackaddr) {
        proc_deallocate(p, stackaddr, stacksize);
    }

    return r;
}

static inline struct Elf64_Phdr *elf_pheader(struct Elf64_Ehdr *hdr) {
	if (!hdr->e_phoff) {
		return NULL;
	}

	return (struct Elf64_Phdr *)((uint64_t)hdr + hdr->e_phoff);
}
static inline struct Elf64_Phdr *elf_segment(struct Elf64_Ehdr *hdr, int idx) {
	uint64_t addr = (uint64_t)elf_pheader(hdr);
	if (!addr) {
		return NULL;
	}

	return (struct Elf64_Phdr *)(addr + (hdr->e_phentsize * idx));
}
static inline struct Elf64_Shdr *elf_sheader(struct Elf64_Ehdr *hdr) {
	if (!hdr->e_shoff) {
		return NULL;
	}

	return (struct Elf64_Shdr *)((uint64_t)hdr + hdr->e_shoff);
}
static inline struct Elf64_Shdr *elf_section(struct Elf64_Ehdr *hdr, int idx) {
	uint64_t addr = (uint64_t)elf_sheader(hdr);
	if (!addr) {
		return NULL;
	}

	return (struct Elf64_Shdr *)(addr + (hdr->e_shentsize * idx));
}

int elf_mapped_size(void *elf, uint64_t *msize) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    if (memcmp(ehdr->e_ident, ElfMagic, 4)) {
        return 1;
    }

    uint64_t s = 0;
    struct Elf64_Phdr *phdr = elf_pheader(ehdr);
    if (phdr) {
        for (int i = 0; i < ehdr->e_phnum; i++) {
            struct Elf64_Phdr *phdr = elf_segment(ehdr, i);

            uint64_t delta = phdr->p_paddr + phdr->p_memsz;
            if (delta > s) {
                s = delta;
            }
        }
    } else {
        for (int i = 0; i < ehdr->e_shnum; i++) {
            struct Elf64_Shdr *shdr = elf_section(ehdr, i);

            uint64_t delta = shdr->sh_addr + shdr->sh_size;
            if (delta > s) {
                s = delta;
            }
        }
    }

    if (msize) {
        *msize = s;
    }

    return 0;
}

int proc_map_elf(struct proc *p, void *elf, void *exec) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    struct Elf64_Phdr *phdr = elf_pheader(ehdr);
    if (phdr) {
        for (int i = 0; i < ehdr->e_phnum; i++) {
            struct Elf64_Phdr *phdr = elf_segment(ehdr, i);

            if (phdr->p_filesz) {
                proc_write_mem(p, (void *)((uint8_t *)exec + phdr->p_paddr), phdr->p_filesz, (void *)((uint8_t *)elf + phdr->p_offset), NULL);
            }
        }
    } else {
        for (int i = 0; i < ehdr->e_shnum; i++) {
            struct Elf64_Shdr *shdr = elf_section(ehdr, i);

            if (!(shdr->sh_flags & SHF_ALLOC)) {
                continue;
            }

            if (shdr->sh_size) {
                proc_write_mem(p, (void *)((uint8_t *)exec + shdr->sh_addr), shdr->sh_size, (void *)((uint8_t *)elf + shdr->sh_offset), NULL);
            }
        }
    }

    return 0;
}

int proc_relocate_elf(struct proc *p, void *elf, void *exec) {
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        struct Elf64_Shdr *shdr = elf_section(ehdr, i);


        if (shdr->sh_type == SHT_REL) {
            for (int j = 0; j < shdr->sh_size / shdr->sh_entsize; j++) {
                struct Elf64_Rela *reltab = &((struct Elf64_Rela *)((uint64_t)ehdr + shdr->sh_offset))[j];
                uint8_t **ref = (uint8_t **)((uint8_t *)exec + reltab->r_offset);
                uint8_t *value = NULL;

                switch (ELF64_R_TYPE(reltab->r_info)) {
                case R_X86_64_RELATIVE:
                    value = (uint8_t *)exec + reltab->r_addend;
                    proc_write_mem(p, ref, sizeof(value), (void *)&value, NULL);
                    break;
                case R_X86_64_64:
                case R_X86_64_JUMP_SLOT:
                case R_X86_64_GLOB_DAT:
                    // not supported
                    break;
                }
            }
        }
    }

    return 0;
}

int proc_load_elf(struct proc *p, void *elf, uint64_t *elfbase, uint64_t *entry) {
    void *elfaddr = NULL;
    uint64_t msize = 0;
    int r = 0;

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)elf;
    r = elf_mapped_size(elf, &msize);
    if (r) {
        goto error;
    }

    msize += (PAGE_SIZE - (msize % PAGE_SIZE));
    r = proc_allocate(p, &elfaddr, msize);
    if (r) {
        goto error;
    }

    r = proc_map_elf(p, elf, elfaddr);
    if (r) {
        goto error;
    }

    r = proc_relocate_elf(p, elf, elfaddr);
    if (r) {
        goto error;
    }

    if (elfbase) {
        *elfbase = (uint64_t)elfaddr;
    }

    if (entry) {
        *entry = (uint64_t)elfaddr + ehdr->e_entry;
    }

error:
    return r;
}

int sys_proc_elf_handle(struct proc *p, char* elf) {
    struct proc_vm_map_entry *entries;
    uint64_t num_entries;
    uint64_t entry;

    if(proc_load_elf(p, elf, NULL, &entry)) {
        return 1;
    }

    if(proc_get_vm_map(p, &entries, &num_entries)) {
        return 1;
    }

    for (int i = 0; i < num_entries; i++) {
        if (entries[i].prot != (PROT_READ | PROT_EXEC)) {
            continue;
        }

        if (!memcmp(entries[i].name, "executable", 10)) {
            proc_mprotect(p, (void *)entries[i].start, (void*)(uint64_t)(entries[i].end - entries[i].start), VM_PROT_ALL);
            break;
        }
    }

    if(proc_create_thread(p, entry)) {
        return 1;
    }

    return 0;
}