#include <syscall.h>
#include "../syscall-nr.h"

/* Invokes syscall NUMBER, passing no arguments, and returns the
   return value as an `int'. */
#define syscall0(NUMBER)                                        \
        ({                                                      \
          int retval;                                           \
          asm volatile                                          \
            ("pushl %[number]; int $0x30; addl $4, %%esp"       \
               : "=a" (retval)                                  \
               : [number] "i" (NUMBER)                          \
               : "memory");                                     \
          retval;                                               \
        })

/* Invokes syscall NUMBER, passing argument ARG0, and returns the
   return value as an `int'. */
#define syscall1(NUMBER, ARG0)                                           \
        ({                                                               \
          int retval;                                                    \
          asm volatile                                                   \
            ("pushl %[arg0]; pushl %[number]; int $0x30; addl $8, %%esp" \
               : "=a" (retval)                                           \
               : [number] "i" (NUMBER),                                  \
                 [arg0] "g" (ARG0)                                       \
               : "memory");                                              \
          retval;                                                        \
        })

/* Invokes syscall NUMBER, passing arguments ARG0 and ARG1, and
   returns the return value as an `int'. */
#define syscall2(NUMBER, ARG0, ARG1)                            \
        ({                                                      \
          int retval;                                           \
          asm volatile                                          \
            ("pushl %[arg1]; pushl %[arg0]; "                   \
             "pushl %[number]; int $0x30; addl $12, %%esp"      \
               : "=a" (retval)                                  \
               : [number] "i" (NUMBER),                         \
                 [arg0] "g" (ARG0),                             \
                 [arg1] "g" (ARG1)                              \
               : "memory");                                     \
          retval;                                               \
        })

/* Invokes syscall NUMBER, passing arguments ARG0, ARG1, and
   ARG2, and returns the return value as an `int'. */
#define syscall3(NUMBER, ARG0, ARG1, ARG2)                      \
        ({                                                      \
          int retval;                                           \
          asm volatile                                          \
            ("pushl %[arg2]; pushl %[arg1]; pushl %[arg0]; "    \
             "pushl %[number]; int $0x30; addl $16, %%esp"      \
               : "=a" (retval)                                  \
               : [number] "i" (NUMBER),                         \
                 [arg0] "g" (ARG0),                             \
                 [arg1] "g" (ARG1),                             \
                 [arg2] "g" (ARG2)                              \
               : "memory");                                     \
          retval;                                               \
        })

void halt (void){
	printf("HALT\n");
	syscall0 (SYS_HALT);
	NOT_REACHED ();
}

void exit (int status){
	printf("EXIT\n");
	syscall1 (SYS_EXIT, status);
	NOT_REACHED ();
}

pid_t exec (const char *file){
	printf("EXEC\n");
	return (pid_t) syscall1 (SYS_EXEC, file);
}

int wait (pid_t pid){
	printf("WAIT\n");
	return syscall1 (SYS_WAIT, pid);
}

bool create (const char *file, unsigned initial_size) {
	printf("CREATE\n");
	return syscall2 (SYS_CREATE, file, initial_size);
}

bool remove (const char *file){
	printf("REMOVE\n");
	return syscall1 (SYS_REMOVE, file);
}

int open (const char *file) {
	printf("OPEN\n");
	return syscall1 (SYS_OPEN, file);
}

int filesize (int fd){
	printf("FILESIZE\n");
	return syscall1 (SYS_FILESIZE, fd);
}

int read (int fd, void *buffer, unsigned size){
	printf("READ\n");
	return syscall3 (SYS_READ, fd, buffer, size);
}

int write (int fd, const void *buffer, unsigned size){
	printf("WRITE\n");
	return syscall3 (SYS_WRITE, fd, buffer, size);
}

void seek (int fd, unsigned position) {
	printf("SEEK\n");
	syscall2 (SYS_SEEK, fd, position);
}

unsigned tell (int fd) {
	printf("TELL\n");
	return syscall1 (SYS_TELL, fd);
}

void close (int fd){
	printf("CLOSE\n");
	syscall1 (SYS_CLOSE, fd);
}

mapid_t mmap (int fd, void *addr){
	printf("MMAP\n");
	return syscall2 (SYS_MMAP, fd, addr);
}

void munmap (mapid_t mapid){
	printf("munmap\n");
	syscall1 (SYS_MUNMAP, mapid);
}

bool chdir (const char *dir){
	printf("CHDIR\n");
	return syscall1 (SYS_CHDIR, dir);
}

bool mkdir (const char *dir) {
	printf("MKDIR\n");
	return syscall1 (SYS_MKDIR, dir);
}

bool readdir (int fd, char name[READDIR_MAX_LEN + 1]){
	printf("READDIR\n");
	return syscall2 (SYS_READDIR, fd, name);
}

bool isdir (int fd) {
	printf("ISDIR\n");
	return syscall1 (SYS_ISDIR, fd);
}

int inumber (int fd){
	printf("INUMBER\n");
	return syscall1 (SYS_INUMBER, fd);
}
