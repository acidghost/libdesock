#define _GNU_SOURCE
#define __USE_GNU
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <desock.h>
#include <peekbuffer.h>
#include <syscall.h>

#ifdef NYX_MODE
#include <nyx.h>
#endif /* NYX_MODE */

static long internal_readv (struct iovec* iov, int len, int* full, int peek, int offset) {
    int read_in = 0;

    if (full) {
        *full = 1;
    }

#ifdef NYX_MODE
    static char data_buffer[(1 << 14)];

    if (peek) {
        for (int i = 0; i < len; ++i) {
            int r = peekbuffer_cp (iov[i].iov_base, iov[i].iov_len, offset);
            offset += r;

            read_in += r;

            if (r < iov[i].iov_len) {
                if (full) {
                    *full = 0;
                }

                break;
            }
        }
    } else {
        size_t total_length = 0;
        for (int i = 0; i < len; ++i) {
            total_length += iov[i].iov_len;
        }

        int i = 0, peek_offset = 0;
        if (peekbuffer_size () > 0) {
            for (i = 0; i < len; ++i) {
                peek_offset = peekbuffer_mv (iov[i].iov_base, iov[i].iov_len);
                read_in += peek_offset;
                if (peek_offset < iov[i].iov_len) {
                    if (full) {
                        *full = 0;
                    }
                    break;
                }
            }
        }

        ssize_t rem_len = total_length - read_in;
        if (rem_len > 0) {
            if (full) {
                *full = 1;
            }

            int to_copy_len = handle_next_packet (data_buffer, rem_len);
            size_t offset = 0;

            for (; i < len; ++i) {
                char* base = ((char*) iov[i].iov_base) + peek_offset;
                size_t iov_len = iov[i].iov_len - peek_offset;
                if (to_copy_len <= iov_len) {
                    memcpy (base, data_buffer + offset, to_copy_len);
                    DEBUG_LOG ("%s: done copying iovec %d\n", __func__, i);
                    offset += to_copy_len;
                    if (full) {
                        *full = to_copy_len == iov_len;
                    }
                    break;
                }
                memcpy (base, data_buffer + offset, iov_len);
                DEBUG_LOG ("%s: done copying iovec %d\n", __func__, i);
                to_copy_len -= iov_len;
                offset += iov_len;
                peek_offset = 0;
            }

            read_in += offset;
        }
    }

#else  /* ! NYX_MODE */
    for (int i = 0; i < len; ++i) {
        int r = 0;

        if (peek) {
            r = peekbuffer_cp (iov[i].iov_base, iov[i].iov_len, offset);
            offset += r;
        } else {
            if (peekbuffer_size () > 0) {
                r = peekbuffer_mv (iov[i].iov_base, iov[i].iov_len);
            }

            if (r < iov[i].iov_len) {
                errno = 0;
                r += syscall_cp (SYS_read, 0, (char*) iov[i].iov_base + r, iov[i].iov_len - r);

                if (errno) {
                    return -1;
                }
            }
        }

        read_in += r;

        if (r < iov[i].iov_len) {
            if (full) {
                *full = 0;
            }

            break;
        }
    }
#endif /* ! NYX_MODE */

    return read_in;
}

ssize_t read (int fd, void* buf, size_t count) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::read(%d, %p, %lu)", gettid (), fd, buf, count);

        int offset = 0;

        if (peekbuffer_size () > 0) {
            offset = peekbuffer_mv (buf, count);
        }

        if (offset < count) {
#ifdef NYX_MODE
            offset += handle_next_packet ((char*) buf + offset, count - offset);
#else  /* ! NYX_MODE */
            errno = 0;
            offset += syscall_cp (SYS_read, 0, (char*) buf + offset, count - offset);

            if (errno) {
                DEBUG_LOG (" = -1\n");
                return -1;
            }
#endif /* ! NYX_MODE */
        }

        DEBUG_LOG (" = %d\n", offset);
        return offset;
    } else {
        return syscall_cp (SYS_read, fd, buf, count);
    }
}

static ssize_t internal_recv (int fd, char* buf, size_t len, int flags) {
    size_t buflen = peekbuffer_size ();
    int offset = 0;

    if (flags & MSG_PEEK) {
        long delta = len - buflen;

        if (delta > 0 && peekbuffer_read (delta) == -1) {
            return -1;
        }

        return peekbuffer_cp (buf, len, 0);
    } else if (buflen > 0) {
        offset = peekbuffer_mv (buf, len);
    }

    if (offset < len) {
#ifdef NYX_MODE
        offset += handle_next_packet (buf + offset, len - offset);
#else  /* ! NYX_MODE */
        errno = 0;
        offset += (syscall_cp (SYS_read, 0, buf + offset, len - offset));

        if (errno) {
            return -1;
        }
#endif /* ! NYX_MODE */
    }

    return offset;
}

ssize_t recvfrom (int fd, void* buf, size_t len, int flags, struct sockaddr* restrict addr,
                  socklen_t* alen) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::recvfrom(%d, %p, %lu, %d, %p, %p)", gettid (), fd, buf, len, flags,
                   addr, alen);

        fill_sockaddr (fd, addr, alen);

        int r = internal_recv (fd, buf, len, flags);
        DEBUG_LOG (" = %d\n", r);
        return r;
    } else {
        return socketcall_cp (recvfrom, fd, buf, len, flags, addr, alen);
    }
}

ssize_t recv (int fd, void* buf, size_t len, int flags) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        int r = internal_recv (fd, buf, len, flags);
        DEBUG_LOG ("[%d] desock::recv(%d, %p, %lu, %d) = %d\n", gettid (), fd, buf, len, flags, r);
        return r;
    } else {
        return socketcall_cp (recvfrom, fd, buf, len, flags, NULL, NULL);
    }
}

ssize_t recvmsg (int fd, struct msghdr* msg, int flags) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::recvmsg(%d, %p, %d)", gettid (), fd, msg, flags);

        if (flags & MSG_PEEK) {
            size_t total_length = 0;

            for (int i = 0; i < msg->msg_iovlen; ++i) {
                total_length += msg->msg_iov[i].iov_len;
            }

            long delta = total_length - peekbuffer_size ();

            if (delta > 0 && peekbuffer_read (delta) == -1) {
                DEBUG_LOG (" = -1\n");
                return -1;
            }
        }

        msg->msg_flags = 0;

        fill_sockaddr (fd, msg->msg_name, &msg->msg_namelen);

        int r = internal_readv (msg->msg_iov, msg->msg_iovlen, NULL, flags & MSG_PEEK, 0);
        DEBUG_LOG (" = %d\n", r);
        return r;
    } else {
        return socketcall_cp (recvmsg, fd, msg, flags, 0, 0, 0);
    }
}

int recvmmsg (int fd, struct mmsghdr* msgvec, unsigned int vlen, int flags,
              struct timespec* timeout) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        DEBUG_LOG ("[%d] desock::recvmmsg(%d, %p, %d, %d, %p)", gettid (), fd, msgvec, vlen, flags,
                   timeout);

        int i;
        int offset = 0;

        if (flags & MSG_PEEK) {
            size_t total_length = 0;

            for (i = 0; i < vlen; ++i) {
                for (int j = 0; j < msgvec[i].msg_hdr.msg_iovlen; ++j) {
                    total_length += msgvec[i].msg_hdr.msg_iov[j].iov_len;
                }
            }

            long delta = total_length - peekbuffer_size ();

            if (delta > 0 && peekbuffer_read (delta) == -1) {
                DEBUG_LOG (" = -1\n");
                return -1;
            }
        }

        for (i = 0; i < vlen; ++i) {
            int full = 0;

            msgvec[i].msg_hdr.msg_flags = 0;

            fill_sockaddr (fd, msgvec[i].msg_hdr.msg_name, &msgvec[i].msg_hdr.msg_namelen);

            msgvec[i].msg_len =
                internal_readv (msgvec[i].msg_hdr.msg_iov, msgvec[i].msg_hdr.msg_iovlen, &full,
                                flags & MSG_PEEK, offset);

            if (msgvec[i].msg_len == -1) {
                DEBUG_LOG (" = -1\n");
                return -1;
            }

            offset += msgvec[i].msg_len;

            if (!full) {
                break;
            }
        }

        int r = (i == vlen || i == 0) ? i : (i + 1);
        DEBUG_LOG (" = %d\n", r);
        return r;
    } else {
        return syscall_cp (SYS_recvmmsg, fd, msgvec, vlen, flags, timeout);
    }
}

ssize_t readv (int fd, struct iovec* iov, int count) {
    if (VALID_FD (fd) && fd_table[fd].desock) {
        int r = internal_readv (iov, count, NULL, 0, 0);
        DEBUG_LOG ("[%d] desock::readv(%d, %p, %d) = %d\n", gettid (), fd, iov, count, r);
        return r;
    } else {
        return syscall_cp (SYS_readv, fd, iov, count);
    }
}
