#include "sockets.h"

bool Sockets::Connect() {
	struct sockaddr_in addr;

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (Socket == -1)
		return false;

	addr.sin_family = AF_INET;
	addr.sin_port = this->port;
	addr.sin_addr.s_addr = inet_addr(this->IP);

	if (connect(Socket, (sockaddr*)&addr, sizeof(addr)) < 0)
		return false;

	return true;
}


Sockets::Sockets(const char* ConnectionAddr) {
	memset(this->IP, 0, 16);
	strcpy_s(this->IP, ConnectionAddr);

	this->port = 8801;
	this->hasConnectionBeenClosed = false;
}

Sockets::~Sockets() {
	if (!hasConnectionBeenClosed)
		Close();
}

void Sockets::Close() {
	hasConnectionBeenClosed = true;

	shutdown(Socket, 2);
	closesocket(Socket);
}

bool Sockets::Send(const char* Data, int Length) {
	int Start = GetTickCount();

	char* CurrentPosition = (char*)Data;
	int DataLeft = Length;
	int SentStatus = 0;

	while (DataLeft > 0) {
		int DataChunkSize = min(1024 * 2, DataLeft);
		if (hasConnectionBeenClosed)
			return false;

		SentStatus = send(Socket, CurrentPosition, DataChunkSize, 0);
		if (SentStatus == -1 && errno != EWOULDBLOCK)
			break;

		DataLeft -= SentStatus;
		CurrentPosition += SentStatus;
	}

	if (SentStatus == -1)
		return false;

	return true;
}

bool Sockets::Receive(char* Data, int Size) {
	int Start = GetTickCount();

	char* CurrentPosition = (char*)Data;
	int DataLeft = Size;
	int ReceiveStatus = 0;

	while (DataLeft > 0) {
		int DataChunkSize = min(1024 * 2, DataLeft);
		if (hasConnectionBeenClosed)
			return false;

		ReceiveStatus = recv(Socket, CurrentPosition, DataChunkSize, 0);
		if (ReceiveStatus == -1 && errno != EWOULDBLOCK)
			break;

		CurrentPosition += ReceiveStatus;
		DataLeft -= ReceiveStatus;
	}

	if (ReceiveStatus == -1)
		return false;

	return true;
}
