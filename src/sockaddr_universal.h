#if !defined(__sockaddr_universal_h__)
#define __sockaddr_universal_h__ 1

#if defined(_WIN32)
//#include <winsock2.h>
#include <WS2tcpip.h>
#else
#include <netinet/in.h>
#endif // defined(_WIN32)

union sockaddr_universal {
    struct sockaddr_storage addr_stor;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr addr;
};

int convert_address(const char *addr_str, unsigned short port, union sockaddr_universal *addr);

#endif // !defined(__sockaddr_universal_h__)
