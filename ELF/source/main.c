#include "../include/main.h"

char bEndRPC = 0;
struct proc *kDebugProc;

void ClientThread(void *vfd) {
	int ret = 1;
	int Socket = (uint64_t)vfd;
	RPC_PACKET* Command = (RPC_PACKET*)alloc(sizeof(RPC_PACKET));
	memset(Command, 0, sizeof(RPC_PACKET));

	if (Receive(Socket, (char*)Command, sizeof(RPC_PACKET))) {
		switch (Command->CommandType) {
			case READ_MEMORY:
				ret = ProcessReadMemory(Socket, Command);
			 	break;
			case WRITE_MEMORY:
				ret = ProcessWriteMemory(Socket, Command);
			 	break;
			case PROCESS_GET_LIST:
				ret = ProcessGetList(Socket, Command);
			 	break;
			case PROCESS_ATTACH:
				ret = ProcessAttach(Socket, Command);
			 	break;
			case PROCESS_DETACH:
				ret = ProcessDetach(Socket, Command);
			 	break;
			case PROCESS_CONTINUE:
				ret = ProcessContinue(Socket, Command);
			 	break;
			case PROCESS_SIGNAL:
				ret = ProcessSignal(Socket, Command);
			 	break;
			case PROCESS_GET_FLAGS:
				ret = ProcessGetFlags(Socket, Command);
				break;
			case PROCESS_GET_REGISTERS:
				ret = ProcessGetRegisters(Socket, Command);
			 	break;
			case PROCESS_SET_REGISTERS:
				ret = ProcessSetRegisters(Socket, Command);
			 	break;
			case PROCESS_SET_SINGLE_STEP:
				ret = ProcessSetStep(Socket, Command);
				break;
			case PROCESS_CLEAR_SINGLE_STEP:
				ret = ProcessClearStep(Socket, Command);
				break;
			case PROCESS_SINGLE_STEP:
				ret = ProcessSingleStep(Socket, Command);
			 	break;
			case PROCESS_LOAD_ELF:
				ret = ProcessLoadElf(Socket, Command);
			 	break;
			case REBOOT_CONSOLE:
				kern_reboot(0);
			 	break;
			case END_RPC:
				bEndRPC = 1;
				break;
			default:
				ret = 0;
			 	break;
		}
	}

	SendReponse(Socket, ret);

	dealloc(Command);

	net_close(Socket);
	kthread_exit();
}

void DebugThread(void *arg) {
	struct sockaddr_in servaddr = { 0 };

	int ClientSocket = -1;
	int ServerSocket = net_socket(AF_INET, SOCK_STREAM, 0);

	int optval = 1;
	net_setsockopt(ServerSocket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&optval, sizeof(int));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = 8801;

	net_bind(ServerSocket, (struct sockaddr *)&servaddr, sizeof(servaddr));
	net_listen(ServerSocket, 100);
	
	while (1) {
		kthread_suspend_check();

		ClientSocket = net_accept(ServerSocket, NULL, NULL);

		if (bEndRPC)
			break;

		if (ClientSocket != -1) {
			int optval = 1;
			net_setsockopt(ClientSocket, SOL_SOCKET, SO_NOSIGPIPE, (void *)&optval, sizeof(int));
			kproc_kthread_add(ClientThread, (void*)((uint64_t)ClientSocket), &kDebugProc, NULL, NULL, 0, "Debug Listener", "Client Thread");
		}
	}

	net_close(ServerSocket);
	kthread_exit();
}

int payload_entry(void *arg) {
	net_disable_copy_checks();

	kproc_create(DebugThread, 0, &kDebugProc, 0, 0, "Debug Listener");

	return 0;
}
