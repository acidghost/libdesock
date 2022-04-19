#ifndef DESOCK_H
#define DESOCK_H

#include <semaphore.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

// Check that we are desocketing at least one of client or server
#ifndef DESOCK_BIND
#ifndef DESOCK_CONNECT
#error "At least one of DESOCK_CONNECT or DESOCK_BIND must be specified"
#endif
#endif

/*
If conns >= MAX_CONNS accept() will block
*/
#ifndef MAX_CONNS
#define MAX_CONNS 1
#endif

extern sem_t sem;

#ifdef DEBUG
#ifdef NYX_MODE
void hprintf(const char*, ...);
#define DEBUG_LOG(...) hprintf(__VA_ARGS__);
#else /* ! NYX_MODE */
void _debug (char*, ...);
#define DEBUG_LOG(...) _debug(__VA_ARGS__);
#endif /* ! NYX_MODE */
#else
#define DEBUG_LOG(...)
#endif

void fill_sockaddr (int, struct sockaddr*, socklen_t*);

#ifdef NYX_MODE
void habort(const char*, ...);
#define _error(...) habort(__VA_ARGS__);
#else /* ! NYX_MODE */
void _error (char*, ...);
#endif /* ! NYX_MODE */

struct fd_entry {
    /* information passed to socket() */
    int domain;
    
    /* flag whether to desock this fd */
    int desock;
    
    /* flag whether this is the server socket */
    int listening;
    
    /* epoll stuff */
    int epfd;
    struct epoll_event ep_event;
};

#ifndef FD_TABLE_SIZE
#define FD_TABLE_SIZE 1024
#endif

extern struct fd_entry fd_table[FD_TABLE_SIZE];
extern int accept_block;
extern int max_fd;
extern const struct sockaddr_in stub_sockaddr_in;
extern const struct sockaddr_in6 stub_sockaddr_in6;
extern const struct sockaddr_un stub_sockaddr_un;

#define VALID_FD(x) (0 <= (x) && (x) < FD_TABLE_SIZE)

#if DESOCK_PORT > 0
#define DESOCK_FD(x, port)                                                                         \
    ((fd_table[(x)].domain == AF_INET || fd_table[(x)].domain == AF_INET6) &&                      \
     (port == htons(DESOCK_PORT)))
#else
#define DESOCK_FD(x, ...) (fd_table[(x)].domain == AF_INET || fd_table[(x)].domain == AF_INET6)
#endif

#ifdef DEBUG
void clear_fd_table_entry(int);
#else
inline void clear_fd_table_entry (int idx) {
    fd_table[idx].epfd = -1;
    fd_table[idx].desock = 0;
    fd_table[idx].listening = 0;
}
#endif

#define MIN(x, y) ((x) < (y) ? (x) : (y))

#endif /* DESOCK_H */
