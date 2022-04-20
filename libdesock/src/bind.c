#ifdef DESOCK_BIND
#include <sys/socket.h>

#define _GNU_SOURCE
#include <unistd.h>

#include <syscall.h>
#include <desock.h>

int bind (int fd, const struct sockaddr* addr, socklen_t len) {
    if (VALID_FD (fd) && DESOCK_FD (fd, ((struct sockaddr_in*) addr)->sin_port)) {
        DEBUG_LOG ("[%d] desock::bind(%d, %p, %d) = 0\n", gettid (), fd, addr, len);
        fd_table[fd].desock = 1;
        return 0;
    } else {
        return socketcall (bind, fd, addr, len, 0, 0, 0);
    }
}

#ifdef DEBUG
int _debug_real_bind (int fd, const struct sockaddr* addr, socklen_t len) {
    return socketcall (bind, fd, addr, len, 0, 0, 0);
}
#endif

#endif
