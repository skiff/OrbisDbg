#pragma once

#include "main.h"

class Sockets {
public:
	char IP[16];
	SOCKET Socket;

	Sockets(const char* ConnectReceiveionAddr);
	~Sockets();

	void Close();
	bool Connect();
	bool Send(const char* Data, int Length);
	bool Receive(char* Data, int Size);

private:
	unsigned short port;
	bool hasConnectionBeenClosed;
};