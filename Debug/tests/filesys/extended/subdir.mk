################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/filesys/extended/child-syn-rw.c \
../tests/filesys/extended/dir-empty-name.c \
../tests/filesys/extended/dir-mk-tree.c \
../tests/filesys/extended/dir-mkdir.c \
../tests/filesys/extended/dir-open.c \
../tests/filesys/extended/dir-over-file.c \
../tests/filesys/extended/dir-rm-cwd.c \
../tests/filesys/extended/dir-rm-parent.c \
../tests/filesys/extended/dir-rm-root.c \
../tests/filesys/extended/dir-rm-tree.c \
../tests/filesys/extended/dir-rmdir.c \
../tests/filesys/extended/dir-under-file.c \
../tests/filesys/extended/dir-vine.c \
../tests/filesys/extended/grow-create.c \
../tests/filesys/extended/grow-dir-lg.c \
../tests/filesys/extended/grow-file-size.c \
../tests/filesys/extended/grow-root-lg.c \
../tests/filesys/extended/grow-root-sm.c \
../tests/filesys/extended/grow-seq-lg.c \
../tests/filesys/extended/grow-seq-sm.c \
../tests/filesys/extended/grow-sparse.c \
../tests/filesys/extended/grow-tell.c \
../tests/filesys/extended/grow-two-files.c \
../tests/filesys/extended/mk-tree.c \
../tests/filesys/extended/syn-rw.c \
../tests/filesys/extended/tar.c 

OBJS += \
./tests/filesys/extended/child-syn-rw.o \
./tests/filesys/extended/dir-empty-name.o \
./tests/filesys/extended/dir-mk-tree.o \
./tests/filesys/extended/dir-mkdir.o \
./tests/filesys/extended/dir-open.o \
./tests/filesys/extended/dir-over-file.o \
./tests/filesys/extended/dir-rm-cwd.o \
./tests/filesys/extended/dir-rm-parent.o \
./tests/filesys/extended/dir-rm-root.o \
./tests/filesys/extended/dir-rm-tree.o \
./tests/filesys/extended/dir-rmdir.o \
./tests/filesys/extended/dir-under-file.o \
./tests/filesys/extended/dir-vine.o \
./tests/filesys/extended/grow-create.o \
./tests/filesys/extended/grow-dir-lg.o \
./tests/filesys/extended/grow-file-size.o \
./tests/filesys/extended/grow-root-lg.o \
./tests/filesys/extended/grow-root-sm.o \
./tests/filesys/extended/grow-seq-lg.o \
./tests/filesys/extended/grow-seq-sm.o \
./tests/filesys/extended/grow-sparse.o \
./tests/filesys/extended/grow-tell.o \
./tests/filesys/extended/grow-two-files.o \
./tests/filesys/extended/mk-tree.o \
./tests/filesys/extended/syn-rw.o \
./tests/filesys/extended/tar.o 

C_DEPS += \
./tests/filesys/extended/child-syn-rw.d \
./tests/filesys/extended/dir-empty-name.d \
./tests/filesys/extended/dir-mk-tree.d \
./tests/filesys/extended/dir-mkdir.d \
./tests/filesys/extended/dir-open.d \
./tests/filesys/extended/dir-over-file.d \
./tests/filesys/extended/dir-rm-cwd.d \
./tests/filesys/extended/dir-rm-parent.d \
./tests/filesys/extended/dir-rm-root.d \
./tests/filesys/extended/dir-rm-tree.d \
./tests/filesys/extended/dir-rmdir.d \
./tests/filesys/extended/dir-under-file.d \
./tests/filesys/extended/dir-vine.d \
./tests/filesys/extended/grow-create.d \
./tests/filesys/extended/grow-dir-lg.d \
./tests/filesys/extended/grow-file-size.d \
./tests/filesys/extended/grow-root-lg.d \
./tests/filesys/extended/grow-root-sm.d \
./tests/filesys/extended/grow-seq-lg.d \
./tests/filesys/extended/grow-seq-sm.d \
./tests/filesys/extended/grow-sparse.d \
./tests/filesys/extended/grow-tell.d \
./tests/filesys/extended/grow-two-files.d \
./tests/filesys/extended/mk-tree.d \
./tests/filesys/extended/syn-rw.d \
./tests/filesys/extended/tar.d 


# Each subdirectory must supply rules for building sources it contributes
tests/filesys/extended/%.o: ../tests/filesys/extended/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


