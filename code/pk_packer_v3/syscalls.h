#define __syscall0(type,name) \
type _##name(void) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name)); \
return(type)__res; \
}

#define __syscall1_no_ret(type,name,type1,arg1) \
type _##name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
 : "0" (__NR_##name),"b" ((long)(arg1))); \
}

#define __syscall1(type,name,type1,arg1) \
type _##name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
 : "0" (__NR_##name),"b" ((long)(arg1))); \
return(type)__res; \
}

#define __syscall2(type,name,type1,arg1,type2,arg2) \
type _##name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2))); \
return(type)__res; \
}

#define __syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type _##name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
                  "d" ((long)(arg3))); \
return(type)__res; \
}
#define __syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type _##name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)),"S" ((long)(arg4))); \
return(type)__res; \
}

#define __syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5) \
type _##name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); \
return(type)__res; \
}
#define __syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5,type6,arg6) \
type _##name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
long __res; \
__asm__ volatile ("push %%ebp ; movl %%eax,%%ebp ; movl %1,%%eax ; int $0x80 ; pop %%ebp" \
        : "=a" (__res) \
        : "i" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5)), \
          "0" ((long)(arg6))); \
return(type)__res; \
}

/* for whatever reason read() through the syscall macro */
/* did not work, so here is the PIC supported way */
/*
static int
_read (int fd, void *buf, int count)
{
  long ret;

  __asm__ __volatile__ ("pushl %%ebx\n\t"
                        "movl %%esi,%%ebx\n\t"
                        "int $0x80\n\t" "popl %%ebx":"=a" (ret)
                        :"0" (SYS_read), "S" ((long) fd),
                        "c" ((long) buf), "d" ((long) count));
  if (ret >= 0) {
    return (int) ret;
  }
  return -1;
}
*/

static inline __syscall1_no_ret(void, exit, int, status);
static inline __syscall3(ssize_t, write, int, fd, const void *, buf, size_t, count);
static inline __syscall3(off_t, lseek, int, fildes, off_t, offset, int, whence);
static inline __syscall2(int, fstat, int, fildes, struct stat * , buf);
static inline __syscall2(int, open, const char *, pathname, int, flags);
static inline __syscall1(int, close, int, fd);
static inline __syscall3(int, read, int, fd, void *, buf, int, count);
static inline __syscall2(int, stat, const char *, path, struct stat *, buf);
static inline __syscall6(void *, mmap2, void *, addr, size_t, len, int, prot, int, flags, int, fd, off_t, offset);
static inline __syscall2(int, munmap, void *, addr, size_t, len);
static inline __syscall3(int, mprotect, void *, addr, size_t, len, int, prot);
