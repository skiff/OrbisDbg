#include "../include/main.h"

void SendReponse(int Socket, int response) {
    RPC_PACKET responsePacket;
    memset((void*)&responsePacket, 0, sizeof(RPC_PACKET));

    responsePacket.commandResponse = response;
    Send(Socket, (char*)&responsePacket, sizeof(RPC_PACKET));
}

int ProcessReadMemory(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	char* Databuffer = (char*)alloc(Data->RRW.length);
	memset(Databuffer, 0, Data->RRW.length);

	struct proc* proc = proc_find_by_name(Data->processName);
	if (proc && Data->RRW.address >= 0x400000 && Data->RRW.length > 0) {
		size_t n = 0;
		ret = proc_read_mem(proc, (void*)Data->RRW.address, (size_t)Data->RRW.length, Databuffer, &n);
	}

	Send(Socket, Databuffer, Data->RRW.length);

	dealloc(Databuffer);

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessWriteMemory(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	char* Databuffer = (char*)alloc(Data->RRW.length);
	memset(Databuffer, 0, Data->RRW.length);

	if (Receive(Socket, Databuffer, Data->RRW.length)) {
		struct proc* proc = proc_find_by_name(Data->processName);

		if (proc && Data->RRW.address >= 0x400000 && Data->RRW.length > 0) {
			size_t n = 0;
			ret = proc_write_mem(proc, (void *)Data->RRW.address, (size_t)Data->RRW.length, Databuffer, &n);
		}
	}
	dealloc(Databuffer);

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessGetList(int Socket, RPC_PACKET* Data) {
    int processCount = get_proc_count();

    RPC_PACKET reply;
    reply.CommandType = PROCESS_GET_LIST;
    reply.LIST.count = processCount;

    Send(Socket, (char*)&reply, sizeof(RPC_PACKET));

    RPC_PROCESSES* processes = (RPC_PROCESSES*)alloc(processCount * sizeof(RPC_PROCESSES));
    memset(processes, 0, processCount * sizeof(RPC_PROCESSES));

    char* sendData = (char*)processes;

	uint64_t kernbase = getkernbase();
	struct proc *p = *(struct proc **)(kernbase + __allproc);

	do {
        processes->pid = p->pid;
		processes->attached = (p->flags & 0x800) != 0;
		memcpy(processes->process, p->p_comm, strlen(p->p_comm) + 1);
        processes++;
	} while ((p = p->p_forw));

    Send(Socket, sendData, processCount * sizeof(RPC_PROCESSES));

    dealloc(processes);

    return RPC_SUCCESS;
}

int ProcessAttach(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	struct proc* proc = proc_find_by_name(Data->processName);
	struct thread *td = curthread();

	if (proc) 
		ret = kern_ptrace(td, PT_ATTACH, proc->pid, 0, 0);

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessDetach(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	struct proc* proc = proc_find_by_name(Data->processName);
	struct thread *td = curthread();

	if (proc) 
		ret = kern_ptrace(td, PT_DETACH, proc->pid, 0, 0);

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessContinue(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	struct proc* proc = proc_find_by_name(Data->processName);
	struct thread *td = curthread();

	if (proc)
		ret = kern_ptrace(td, PT_CONTINUE, proc->pid, (void*)1, 0);
	
    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessSetStep(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	struct proc* proc = proc_find_by_name(Data->processName);
	struct thread *td = curthread();

	if (proc)
		ret = kern_ptrace(td, PT_SETSTEP, proc->pid, 0, 0);
	
    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessClearStep(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	struct proc* proc = proc_find_by_name(Data->processName);
	struct thread *td = curthread();

	if (proc)
		ret = kern_ptrace(td, PT_CLEARSTEP, proc->pid, 0, 0);

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessSingleStep(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	struct proc* proc = proc_find_by_name(Data->processName);
	struct thread *td = curthread();

	if (proc)
		ret = kern_ptrace(td, PT_STEP, proc->pid, (void*)1, 0);

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessGetRegisters(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	struct proc* proc = proc_find_by_name(Data->processName);
	struct thread *td = curthread();

	if (proc) {
		struct reg Registers;
		memset(&Registers, 0, sizeof(struct reg));
		ret = kern_ptrace(td, PT_GETREGS, proc->pid, (void*)&Registers, 0);

        Send(Socket, (char*)&Registers, sizeof(struct reg));
	} 

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessSetRegisters(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	struct proc* proc = proc_find_by_name(Data->processName);
	struct thread *td = curthread();

	if (proc) {
		struct reg Registers;
		memset(&Registers, 0, sizeof(struct reg));

		if (Receive(Socket, (char*)&Registers, sizeof(struct reg)))
			ret = kern_ptrace(td, PT_SETREGS, proc->pid, (void*)&Registers, 0);
	} 

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessSignal(int Socket, RPC_PACKET* Data) {
    int ret = -1;
	struct proc* proc = proc_find_by_name(Data->processName);

	if (proc)
		ret = kern_psignal(proc, Data->SIG.signal);

    if(ret == -1)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}

int ProcessGetFlags(int Socket, RPC_PACKET* Data) {
	int ret = 0;
	struct proc* proc = proc_find_by_name(Data->processName);
	if(proc) {
		char buffer[4];
		memcpy(&buffer, (void*)&proc->flags, 4);
		Send(Socket, buffer, 4);
		ret = 1;
	}

	return ret;
}

int ProcessLoadElf(int Socket, RPC_PACKET* Data) {
    int ret = 1;
	char* Databuffer = (char*)alloc(Data->ELF.length);
	memset(Databuffer, 0, Data->ELF.length);

	if (Receive(Socket, Databuffer, Data->ELF.length)) {
		struct proc* proc = proc_find_by_name(Data->processName);

		if (proc) {
			ret = sys_proc_elf_handle(proc, Databuffer);
		}
	}
    
	dealloc(Databuffer);

    if(ret)
        return RPC_FAILURE;

    return RPC_SUCCESS;
}