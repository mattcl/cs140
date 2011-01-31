################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/userprog/args.c \
../tests/userprog/bad-jump.c \
../tests/userprog/bad-jump2.c \
../tests/userprog/bad-read.c \
../tests/userprog/bad-read2.c \
../tests/userprog/bad-write.c \
../tests/userprog/bad-write2.c \
../tests/userprog/boundary.c \
../tests/userprog/child-bad.c \
../tests/userprog/child-close.c \
../tests/userprog/child-rox.c \
../tests/userprog/child-simple.c \
../tests/userprog/close-bad-fd.c \
../tests/userprog/close-normal.c \
../tests/userprog/close-stdin.c \
../tests/userprog/close-stdout.c \
../tests/userprog/close-twice.c \
../tests/userprog/create-bad-ptr.c \
../tests/userprog/create-bound.c \
../tests/userprog/create-empty.c \
../tests/userprog/create-exists.c \
../tests/userprog/create-long.c \
../tests/userprog/create-normal.c \
../tests/userprog/create-null.c \
../tests/userprog/exec-arg.c \
../tests/userprog/exec-bad-ptr.c \
../tests/userprog/exec-missing.c \
../tests/userprog/exec-multiple.c \
../tests/userprog/exec-once.c \
../tests/userprog/exit.c \
../tests/userprog/halt.c \
../tests/userprog/multi-child-fd.c \
../tests/userprog/multi-recurse.c \
../tests/userprog/open-bad-ptr.c \
../tests/userprog/open-boundary.c \
../tests/userprog/open-empty.c \
../tests/userprog/open-missing.c \
../tests/userprog/open-normal.c \
../tests/userprog/open-null.c \
../tests/userprog/open-twice.c \
../tests/userprog/read-bad-fd.c \
../tests/userprog/read-bad-ptr.c \
../tests/userprog/read-boundary.c \
../tests/userprog/read-normal.c \
../tests/userprog/read-stdout.c \
../tests/userprog/read-zero.c \
../tests/userprog/rox-child.c \
../tests/userprog/rox-multichild.c \
../tests/userprog/rox-simple.c \
../tests/userprog/sc-bad-arg.c \
../tests/userprog/sc-bad-sp.c \
../tests/userprog/sc-boundary-2.c \
../tests/userprog/sc-boundary.c \
../tests/userprog/wait-bad-pid.c \
../tests/userprog/wait-killed.c \
../tests/userprog/wait-simple.c \
../tests/userprog/wait-twice.c \
../tests/userprog/write-bad-fd.c \
../tests/userprog/write-bad-ptr.c \
../tests/userprog/write-boundary.c \
../tests/userprog/write-normal.c \
../tests/userprog/write-stdin.c \
../tests/userprog/write-zero.c 

OBJS += \
./tests/userprog/args.o \
./tests/userprog/bad-jump.o \
./tests/userprog/bad-jump2.o \
./tests/userprog/bad-read.o \
./tests/userprog/bad-read2.o \
./tests/userprog/bad-write.o \
./tests/userprog/bad-write2.o \
./tests/userprog/boundary.o \
./tests/userprog/child-bad.o \
./tests/userprog/child-close.o \
./tests/userprog/child-rox.o \
./tests/userprog/child-simple.o \
./tests/userprog/close-bad-fd.o \
./tests/userprog/close-normal.o \
./tests/userprog/close-stdin.o \
./tests/userprog/close-stdout.o \
./tests/userprog/close-twice.o \
./tests/userprog/create-bad-ptr.o \
./tests/userprog/create-bound.o \
./tests/userprog/create-empty.o \
./tests/userprog/create-exists.o \
./tests/userprog/create-long.o \
./tests/userprog/create-normal.o \
./tests/userprog/create-null.o \
./tests/userprog/exec-arg.o \
./tests/userprog/exec-bad-ptr.o \
./tests/userprog/exec-missing.o \
./tests/userprog/exec-multiple.o \
./tests/userprog/exec-once.o \
./tests/userprog/exit.o \
./tests/userprog/halt.o \
./tests/userprog/multi-child-fd.o \
./tests/userprog/multi-recurse.o \
./tests/userprog/open-bad-ptr.o \
./tests/userprog/open-boundary.o \
./tests/userprog/open-empty.o \
./tests/userprog/open-missing.o \
./tests/userprog/open-normal.o \
./tests/userprog/open-null.o \
./tests/userprog/open-twice.o \
./tests/userprog/read-bad-fd.o \
./tests/userprog/read-bad-ptr.o \
./tests/userprog/read-boundary.o \
./tests/userprog/read-normal.o \
./tests/userprog/read-stdout.o \
./tests/userprog/read-zero.o \
./tests/userprog/rox-child.o \
./tests/userprog/rox-multichild.o \
./tests/userprog/rox-simple.o \
./tests/userprog/sc-bad-arg.o \
./tests/userprog/sc-bad-sp.o \
./tests/userprog/sc-boundary-2.o \
./tests/userprog/sc-boundary.o \
./tests/userprog/wait-bad-pid.o \
./tests/userprog/wait-killed.o \
./tests/userprog/wait-simple.o \
./tests/userprog/wait-twice.o \
./tests/userprog/write-bad-fd.o \
./tests/userprog/write-bad-ptr.o \
./tests/userprog/write-boundary.o \
./tests/userprog/write-normal.o \
./tests/userprog/write-stdin.o \
./tests/userprog/write-zero.o 

C_DEPS += \
./tests/userprog/args.d \
./tests/userprog/bad-jump.d \
./tests/userprog/bad-jump2.d \
./tests/userprog/bad-read.d \
./tests/userprog/bad-read2.d \
./tests/userprog/bad-write.d \
./tests/userprog/bad-write2.d \
./tests/userprog/boundary.d \
./tests/userprog/child-bad.d \
./tests/userprog/child-close.d \
./tests/userprog/child-rox.d \
./tests/userprog/child-simple.d \
./tests/userprog/close-bad-fd.d \
./tests/userprog/close-normal.d \
./tests/userprog/close-stdin.d \
./tests/userprog/close-stdout.d \
./tests/userprog/close-twice.d \
./tests/userprog/create-bad-ptr.d \
./tests/userprog/create-bound.d \
./tests/userprog/create-empty.d \
./tests/userprog/create-exists.d \
./tests/userprog/create-long.d \
./tests/userprog/create-normal.d \
./tests/userprog/create-null.d \
./tests/userprog/exec-arg.d \
./tests/userprog/exec-bad-ptr.d \
./tests/userprog/exec-missing.d \
./tests/userprog/exec-multiple.d \
./tests/userprog/exec-once.d \
./tests/userprog/exit.d \
./tests/userprog/halt.d \
./tests/userprog/multi-child-fd.d \
./tests/userprog/multi-recurse.d \
./tests/userprog/open-bad-ptr.d \
./tests/userprog/open-boundary.d \
./tests/userprog/open-empty.d \
./tests/userprog/open-missing.d \
./tests/userprog/open-normal.d \
./tests/userprog/open-null.d \
./tests/userprog/open-twice.d \
./tests/userprog/read-bad-fd.d \
./tests/userprog/read-bad-ptr.d \
./tests/userprog/read-boundary.d \
./tests/userprog/read-normal.d \
./tests/userprog/read-stdout.d \
./tests/userprog/read-zero.d \
./tests/userprog/rox-child.d \
./tests/userprog/rox-multichild.d \
./tests/userprog/rox-simple.d \
./tests/userprog/sc-bad-arg.d \
./tests/userprog/sc-bad-sp.d \
./tests/userprog/sc-boundary-2.d \
./tests/userprog/sc-boundary.d \
./tests/userprog/wait-bad-pid.d \
./tests/userprog/wait-killed.d \
./tests/userprog/wait-simple.d \
./tests/userprog/wait-twice.d \
./tests/userprog/write-bad-fd.d \
./tests/userprog/write-bad-ptr.d \
./tests/userprog/write-boundary.d \
./tests/userprog/write-normal.d \
./tests/userprog/write-stdin.d \
./tests/userprog/write-zero.d 


# Each subdirectory must supply rules for building sources it contributes
tests/userprog/%.o: ../tests/userprog/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


