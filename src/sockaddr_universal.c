#include <stdio.h>
#include <assert.h>

#include "sockaddr_universal.h"

int convert_address(const char *addr_str, unsigned short port, union sockaddr_universal *addr)
{
    struct addrinfo hints = { 0 }, *ai = NULL;
    int status;
    char port_buffer[6] = { 0 };
    int result = -1;

    if (addr_str == NULL || port == 0 || addr == NULL) {
        return result;
    }

    sprintf(port_buffer, "%hu", port);

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

    if ((status = getaddrinfo(addr_str, port_buffer, &hints, &ai)) != 0) {
        return result;
    }

    // Note, we're taking the first valid address, there may be more than one
    switch (ai->ai_family) {
    case AF_INET:
        addr->addr4 = *(const struct sockaddr_in *) ai->ai_addr;
        addr->addr4.sin_port = htons(port);
        result = 0;
        break;
    case AF_INET6:
        addr->addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
        addr->addr6.sin6_port = htons(port);
        result = 0;
        break;
    default:
        assert(0);
        break;
    }

    freeaddrinfo(ai);
    return result;
}
