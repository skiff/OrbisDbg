#pragma once

struct reg {
	uint64_t r_r15;
	uint64_t r_r14;
	uint64_t r_r13;
	uint64_t r_r12;
	uint64_t r_r11;
	uint64_t r_r10;
	uint64_t r_r9;
	uint64_t r_r8;
	uint64_t r_rdi;
	uint64_t r_rsi;
	uint64_t r_rbp;
	uint64_t r_rbx;
	uint64_t r_rdx;
	uint64_t r_rcx;
	uint64_t r_rax;
	uint32_t r_trapno;
	uint16_t r_fs; // 0x7C
	uint16_t r_gs; // 0x7E
	uint32_t r_err;
	uint16_t r_es;
	uint16_t r_ds;
	uint64_t r_rip;
	uint64_t r_cs;
	uint64_t r_rflags;
	uint64_t r_rsp;
	uint64_t r_ss;
};

#pragma pack(push, 1)
enum RPC_RESPONSE {
	RPC_FAILURE = 0,
	RPC_SUCCESS = 1,
};

enum RPC_CMD {
	READ_MEMORY = 1,
	WRITE_MEMORY = 2,
	PROCESS_GET_LIST = 3,
	PROCESS_ATTACH = 4,
	PROCESS_DETACH = 5,
	PROCESS_CONTINUE = 6,
	PROCESS_SIGNAL = 7,
	PROCESS_GET_FLAGS = 8,
	PROCESS_GET_REGISTERS = 9,
	PROCESS_SET_REGISTERS = 10,
	PROCESS_SET_SINGLE_STEP = 11,
	PROCESS_CLEAR_SINGLE_STEP = 12,
	PROCESS_SINGLE_STEP = 13,
	PROCESS_LOAD_ELF = 14,
	REBOOT_CONSOLE = 15,
	END_RPC = 16,
};

typedef struct {
	uint32_t count;
} RPC_PROCESS_LIST;

typedef struct {
	uint32_t pid;
	uint32_t attached;
	char process[32];
} RPC_PROCESSES;

typedef struct {
	uint64_t address;
	uint32_t length;
} RPC_READ_WRITE;

typedef struct {
	uint64_t signal;
	uint64_t address;
} RPC_SIGNAL;

typedef struct {
	uint32_t length;
} RPC_LOAD_ELF;

typedef struct {
	char processName[32];
	int commandResponse;
	RPC_CMD CommandType;
	RPC_READ_WRITE RRW;
	RPC_SIGNAL SIG;
	RPC_LOAD_ELF ELF;
	RPC_PROCESS_LIST LIST;
} RPC_PACKET;
#pragma pack(pop)