/*
This file is part of NYX.

Copyright (c) 2021 Sergej Schumilo
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#ifdef NYX_MODE
#define _GNU_SOURCE

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifndef __MINGW64__
#include <sys/mman.h>
#endif

#ifdef __MINGW64__
#ifndef uint64_t
#define uint64_t UINT64
#endif
#ifndef int32_t
#define int32_t INT32
#endif
#ifndef uint8_t
#define uint8_t UINT8
#endif
#else
#include <stdint.h>
#endif

#include <desock.h>
#include <musl-features.h>
#include <nyx.h>

#define HYPERCALL_KAFL_RAX_ID 0x01f
#define HYPERCALL_KAFL_ACQUIRE 0
#define HYPERCALL_KAFL_GET_PAYLOAD 1

/* deprecated */
#define HYPERCALL_KAFL_GET_PROGRAM 2
/* deprecated */
#define HYPERCALL_KAFL_GET_ARGV 3

#define HYPERCALL_KAFL_RELEASE 4
#define HYPERCALL_KAFL_SUBMIT_CR3 5
#define HYPERCALL_KAFL_SUBMIT_PANIC 6

/* deprecated */
#define HYPERCALL_KAFL_SUBMIT_KASAN 7

#define HYPERCALL_KAFL_PANIC 8

/* deprecated */
#define HYPERCALL_KAFL_KASAN 9
#define HYPERCALL_KAFL_LOCK 10

/* deprecated */
#define HYPERCALL_KAFL_INFO 11

#define HYPERCALL_KAFL_NEXT_PAYLOAD 12
#define HYPERCALL_KAFL_PRINTF 13

/* deprecated */
#define HYPERCALL_KAFL_PRINTK_ADDR 14
/* deprecated */
#define HYPERCALL_KAFL_PRINTK 15

/* user space only hypercalls */
#define HYPERCALL_KAFL_USER_RANGE_ADVISE 16
#define HYPERCALL_KAFL_USER_SUBMIT_MODE 17
#define HYPERCALL_KAFL_USER_FAST_ACQUIRE 18
/* 19 is already used for exit reason KVM_EXIT_KAFL_TOPA_MAIN_FULL */
#define HYPERCALL_KAFL_USER_ABORT 20
#define HYPERCALL_KAFL_RANGE_SUBMIT 29
#define HYPERCALL_KAFL_REQ_STREAM_DATA 30
#define HYPERCALL_KAFL_PANIC_EXTENDED 32

#define HYPERCALL_KAFL_CREATE_TMP_SNAPSHOT 33
#define HYPERCALL_KAFL_DEBUG_TMP_SNAPSHOT 34 /* hypercall for debugging / development purposes */

#define HYPERCALL_KAFL_GET_HOST_CONFIG 35
#define HYPERCALL_KAFL_SET_AGENT_CONFIG 36

#define HYPERCALL_KAFL_DUMP_FILE 37

#define HYPERCALL_KAFL_REQ_STREAM_DATA_BULK 38
#define HYPERCALL_KAFL_PERSIST_PAGE_PAST_SNAPSHOT 39

#define HPRINTF_MAX_SIZE 0x1000 /* up to 4KB hprintf strings */

/* specific defines to enable support for NYX hypercalls on unmodified KVM
 * builds */
/* PIO port number used by VMWare backdoor */
#define VMWARE_PORT 0x5658
/* slightly changed RAX_ID to avoid vmware backdoor collisions */
#define HYPERCALL_KAFL_RAX_ID_VMWARE 0x8080801f

#if defined(__i386__)

#define KAFL_HYPERCALL_NO_PT(_rbx, _rcx)                                                           \
    ({                                                                                             \
        uint32_t _rax = HYPERCALL_KAFL_RAX_ID_VMWARE;                                              \
        do {                                                                                       \
            uint32_t _rdx = VMWARE_PORT;                                                           \
            asm volatile("movl %1, %%ecx;"                                                         \
                         "movl %2, %%ebx;"                                                         \
                         "movl %3, %%eax;"                                                         \
                         "movl %4, %%edx;"                                                         \
                         "outl %%eax, %%dx;"                                                       \
                         "movl %%eax, %0;"                                                         \
                         : "=a"(_rax)                                                              \
                         : "g"(_rcx), "r"(_rbx), "g"(_rax), "g"(_rdx)                              \
                         : "ecx", "ebx", "edx");                                                   \
        } while (0);                                                                               \
        _rax;                                                                                      \
    })

#define KAFL_HYPERCALL_PT(_rbx, _rcx)                                                              \
    ({                                                                                             \
        uint32_t _rax = HYPERCALL_KAFL_RAX_ID;                                                     \
        do {                                                                                       \
            asm volatile("movl %1, %%ecx;"                                                         \
                         "movl %2, %%ebx;"                                                         \
                         "movl %3, %%eax;"                                                         \
                         "vmcall;"                                                                 \
                         "movl %%eax, %0;"                                                         \
                         : "=a"(_rax)                                                              \
                         : "r"(_rcx), "r"(_rbx), "r"(_rax)                                         \
                         : "ecx", "ebx");                                                          \
        } while (0);                                                                               \
        _rax;                                                                                      \
    })

#else /* ! defined(__i386__) */

#define KAFL_HYPERCALL_NO_PT(_rbx, _rcx)                                                           \
    ({                                                                                             \
        uint64_t _rax = HYPERCALL_KAFL_RAX_ID_VMWARE;                                              \
        do {                                                                                       \
            uint64_t _rdx = VMWARE_PORT;                                                           \
            asm volatile("movq %1, %%rcx;"                                                         \
                         "movq %2, %%rbx;"                                                         \
                         "movq %3, %%rax;"                                                         \
                         "movq %4, %%rdx;"                                                         \
                         "outl %%eax, %%dx;"                                                       \
                         "movq %%rax, %0;"                                                         \
                         : "=a"(_rax)                                                              \
                         : "r"(_rcx), "r"(_rbx), "r"(_rax), "r"(_rdx)                              \
                         : "rcx", "rbx", "rdx");                                                   \
        } while (0);                                                                               \
        _rax;                                                                                      \
    })

#define KAFL_HYPERCALL_PT(_rbx, _rcx)                                                              \
    ({                                                                                             \
        uint64_t _rax = HYPERCALL_KAFL_RAX_ID;                                                     \
        do {                                                                                       \
            asm volatile("movq %1, %%rcx;"                                                         \
                         "movq %2, %%rbx;"                                                         \
                         "movq %3, %%rax;"                                                         \
                         "vmcall;"                                                                 \
                         "movq %%rax, %0;"                                                         \
                         : "=a"(_rax)                                                              \
                         : "r"(_rcx), "r"(_rbx), "r"(_rax)                                         \
                         : "rcx", "rbx");                                                          \
        } while (0);                                                                               \
        _rax;                                                                                      \
    })

#endif /* ! defined(__i386__) */

#ifndef NO_PT_NYX
#define NO_PT_NYX 1
#endif

#if defined(__i386__)

#if NYX_MODE == NO_PT_NYX
static inline uint32_t kAFL_hypercall (uint32_t rbx, uint32_t rcx) {
    return KAFL_HYPERCALL_NO_PT (rbx, rcx);
}
#else  /* ! NO_PT_NYX */
static inline uint32_t kAFL_hypercall (uint32_t rbx, uint32_t rcx) {
    return KAFL_HYPERCALL_PT (rbx, rcx);
}
#endif /* ! NO_PT_NYX */

#elif defined(__x86_64__)

#if NYX_MODE == NO_PT_NYX
static inline uint64_t kAFL_hypercall (uint64_t rbx, uint64_t rcx) {
    return KAFL_HYPERCALL_NO_PT (rbx, rcx);
}
#else  /* ! NO_PT_NYX */
static inline uint64_t kAFL_hypercall (uint64_t rbx, uint64_t rcx) {
    return KAFL_HYPERCALL_PT (rbx, rcx);
}
#endif /* ! NO_PT_NYX */

#endif /* defined(__x86_64__) */

static inline uint8_t alloc_hprintf_buffer (uint8_t** hprintf_buffer) {
    if (!*hprintf_buffer) {
#ifdef __MINGW64__
        *hprintf_buffer = (uint8_t*) VirtualAlloc (0, HPRINTF_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);
#else
        *hprintf_buffer = mmap ((void*) NULL, HPRINTF_MAX_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
        if (!*hprintf_buffer) {
            return 0;
        }
    }
    return 1;
}

void hprintf (const char* format, ...) {
    static uint8_t* hprintf_buffer = NULL;
    va_list args;
    va_start (args, format);
    if (alloc_hprintf_buffer (&hprintf_buffer)) {
        vsnprintf ((char*) hprintf_buffer, HPRINTF_MAX_SIZE, format, args);
        kAFL_hypercall (HYPERCALL_KAFL_PRINTF, (uintptr_t) hprintf_buffer);
    }
    va_end (args);
}

void habort (const char* format, ...) {
    static uint8_t habort_buffer[1024] = {0};
    va_list args;
    va_start (args, format);
    vsnprintf ((char*) habort_buffer, sizeof (habort_buffer), format, args);
    kAFL_hypercall (HYPERCALL_KAFL_PRINTF, (uintptr_t) habort_buffer);
    va_end (args);
}

ssize_t call_vm (void* data, size_t max_size, bool return_pkt_size, bool disable_dump_mode);

ssize_t __dummy_call_vm (void* data, size_t max_size, bool return_pkt_size,
                         bool disable_dump_mode) {
    habort ("call_vm is not implemented, have you preloaded the main library?\n");
    return -1;
}

weak_alias (__dummy_call_vm, call_vm);

void nyx_init_start (void);

void __dummy_nyx_init_start (void) {
    habort ("nyx_init_start is not implemented, have you preloaded the main library?\n");
}

weak_alias (__dummy_nyx_init_start, nyx_init_start);

static inline void init_nyx (void) {
    DEBUG_LOG ("[%d] desock::%s\n", gettid (), __func__);
    static bool init_done = false;
    if (!init_done) {
        DEBUG_LOG ("%s: init_done = false\n", __func__);
        nyx_init_start ();
        init_done = true;
    }
}

int handle_next_packet (void* buf, size_t len) {
    DEBUG_LOG ("[%d] desock::%s(%p, %lu)", gettid (), __func__, buf, len);

    init_nyx ();

    ssize_t data_len = call_vm (buf, len, true, false);

    if (data_len == -1) {
        DEBUG_LOG (" = -1\n");
        /* at this point our interpreter is out of data -> terminate */
        kAFL_hypercall (HYPERCALL_KAFL_RELEASE, 0);
    }
    return data_len;
}
#endif /* NYX_MODE */
