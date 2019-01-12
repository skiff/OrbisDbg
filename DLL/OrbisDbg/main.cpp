#include "main.h"

int GetStatus(Sockets* sock) {
	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));

	if (!sock->Receive((char*)&data, sizeof(RPC_PACKET)))
		return 0;

	return data.commandResponse;
}

extern "C" __declspec(dllexport) int ProcessReadMemory(const char* ip, const char* process, unsigned long long address, int length, char* out) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = READ_MEMORY;
	data.RRW.address = address;
	data.RRW.length = length;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	if (!Sock->Receive(out, length)) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessWriteMemory(const char* ip, const char* process, unsigned long long address, int length, char* in) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = WRITE_MEMORY;
	data.RRW.address = address;
	data.RRW.length = length;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	if (!Sock->Send(in, length)) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessGetList(const char* ip, char* out) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	data.CommandType = PROCESS_GET_LIST;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	RPC_PACKET listPacket;
	if (!Sock->Receive((char*)&listPacket, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	if (!Sock->Receive(out, listPacket.LIST.count * sizeof(RPC_PROCESSES))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessAttach(const char* ip, const char* process) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_ATTACH;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessDetach(const char* ip, const char* process) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_DETACH;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessContinue(const char* ip, const char* process) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_CONTINUE;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessSignal(const char* ip, const char* process, int signal) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_SIGNAL;
	data.SIG.signal = signal;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessGetRegisters(const char* ip, const char* process, char* out) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_GET_REGISTERS;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	if (!Sock->Receive(out, sizeof(reg))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessSetRegisters(const char* ip, const char* process, char* in) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_SET_REGISTERS;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	if (!Sock->Send(in, sizeof(reg))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessSetSingleStep(const char* ip, const char* process) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_SET_SINGLE_STEP;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessClearSingleStep(const char* ip, const char* process) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_CLEAR_SINGLE_STEP;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessSingleStep(const char* ip, const char* process) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_SINGLE_STEP;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int ProcessGetFlags(const char* ip, const char* process, char* out) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_GET_FLAGS;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	if (!Sock->Receive(out, 4)) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int InjectELF(const char* ip, const char* process, char* in, unsigned int size) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	strcpy_s(data.processName, process);
	data.CommandType = PROCESS_LOAD_ELF;
	data.ELF.length = size;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	if (!Sock->Send(in, size)) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();
	return status;
}

extern "C" __declspec(dllexport) int RebootConsole(const char* ip) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	data.CommandType = REBOOT_CONSOLE;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	Sock->Close();
	return 1;
}

extern "C" __declspec(dllexport) int EndRPC(const char* ip) {
	Sockets* Sock = new Sockets(ip);
	if (!Sock->Connect())
		return 0;

	RPC_PACKET data;
	memset(&data, 0, sizeof(RPC_PACKET));
	data.CommandType = END_RPC;

	if (!Sock->Send((char*)&data, sizeof(RPC_PACKET))) {
		Sock->Close();
		return 0;
	}

	int status = GetStatus(Sock);
	Sock->Close();

	Sock->Connect();
	Sock->Close();

	return status;
}