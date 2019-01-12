#include "main.h"

#pragma pack(push,1)

typedef enum {
    RPC_FAILURE = 0,
    RPC_SUCCESS = 1,
} RPC_RESPONSE;

typedef enum {
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
} RPC_CMD;

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
	int32_t length;
} RPC_READ_WRITE;

typedef struct {
    uint64_t signal;
    uint64_t address;
} RPC_SIGNAL;

typedef struct {
    int32_t length;
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

void SendReponse(int Socket, int response);

int ProcessReadMemory(int Socket, RPC_PACKET* Data);
int ProcessWriteMemory(int Socket, RPC_PACKET* Data);
int ProcessGetList(int Socket, RPC_PACKET* Data);
int ProcessAttach(int Socket, RPC_PACKET* Data);
int ProcessDetach(int Socket, RPC_PACKET* Data);
int ProcessContinue(int Socket, RPC_PACKET* Data);
int ProcessSetStep(int Socket, RPC_PACKET* Data);
int ProcessClearStep(int Socket, RPC_PACKET* Data);
int ProcessSingleStep(int Socket, RPC_PACKET* Data);
int ProcessGetRegisters(int Socket, RPC_PACKET* Data);
int ProcessSetRegisters(int Socket, RPC_PACKET* Data);
int ProcessSignal(int Socket, RPC_PACKET* Data);
int ProcessGetFlags(int Socket, RPC_PACKET* Data);
int ProcessLoadElf(int Socket, RPC_PACKET* Data);