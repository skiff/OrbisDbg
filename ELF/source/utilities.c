#include "../include/main.h"

uint64_t getkernbase() {
	return __readmsr(0xC0000082) - __Xfast_syscall;
}

void *alloc(uint32_t size) {
	return malloc(size, M_TEMP, 2);
}

void dealloc(void *addr) {
	free(addr, M_TEMP);
}

void printf(char* fmt, ...) {
	char buffer[0x400] = { 0 };

	va_list args;
	va_start(args, fmt);
	vsprintf(buffer, fmt, args);

	int sock = net_socket(AF_INET, SOCK_STREAM, 0);

	int optval = 1;
	net_setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&optval, sizeof(int));

	struct sockaddr_in sockAddr = { 0 };
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = 29975;
	sockAddr.sin_addr.s_addr = 0x7F8EC20A;

	net_connect(sock, (struct sockaddr*)&sockAddr, sizeof(struct sockaddr));
	net_send(sock, buffer, 0x400);
	net_close(sock);

	va_end(args);
}

int wait4(int wpid, int *status, int options, void *rusage) {
	struct thread* td = curthread();
    return kern_wait(td, wpid, status, options, rusage);
}