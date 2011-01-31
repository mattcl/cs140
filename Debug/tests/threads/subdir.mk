################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/threads/alarm-negative.c \
../tests/threads/alarm-priority.c \
../tests/threads/alarm-simultaneous.c \
../tests/threads/alarm-wait.c \
../tests/threads/alarm-zero.c \
../tests/threads/mlfqs-block.c \
../tests/threads/mlfqs-fair.c \
../tests/threads/mlfqs-load-1.c \
../tests/threads/mlfqs-load-60.c \
../tests/threads/mlfqs-load-avg.c \
../tests/threads/mlfqs-recent-1.c \
../tests/threads/priority-change.c \
../tests/threads/priority-condvar.c \
../tests/threads/priority-donate-chain.c \
../tests/threads/priority-donate-lower.c \
../tests/threads/priority-donate-multiple.c \
../tests/threads/priority-donate-multiple2.c \
../tests/threads/priority-donate-nest.c \
../tests/threads/priority-donate-one.c \
../tests/threads/priority-donate-sema.c \
../tests/threads/priority-fifo.c \
../tests/threads/priority-preempt.c \
../tests/threads/priority-sema.c \
../tests/threads/tests.c 

OBJS += \
./tests/threads/alarm-negative.o \
./tests/threads/alarm-priority.o \
./tests/threads/alarm-simultaneous.o \
./tests/threads/alarm-wait.o \
./tests/threads/alarm-zero.o \
./tests/threads/mlfqs-block.o \
./tests/threads/mlfqs-fair.o \
./tests/threads/mlfqs-load-1.o \
./tests/threads/mlfqs-load-60.o \
./tests/threads/mlfqs-load-avg.o \
./tests/threads/mlfqs-recent-1.o \
./tests/threads/priority-change.o \
./tests/threads/priority-condvar.o \
./tests/threads/priority-donate-chain.o \
./tests/threads/priority-donate-lower.o \
./tests/threads/priority-donate-multiple.o \
./tests/threads/priority-donate-multiple2.o \
./tests/threads/priority-donate-nest.o \
./tests/threads/priority-donate-one.o \
./tests/threads/priority-donate-sema.o \
./tests/threads/priority-fifo.o \
./tests/threads/priority-preempt.o \
./tests/threads/priority-sema.o \
./tests/threads/tests.o 

C_DEPS += \
./tests/threads/alarm-negative.d \
./tests/threads/alarm-priority.d \
./tests/threads/alarm-simultaneous.d \
./tests/threads/alarm-wait.d \
./tests/threads/alarm-zero.d \
./tests/threads/mlfqs-block.d \
./tests/threads/mlfqs-fair.d \
./tests/threads/mlfqs-load-1.d \
./tests/threads/mlfqs-load-60.d \
./tests/threads/mlfqs-load-avg.d \
./tests/threads/mlfqs-recent-1.d \
./tests/threads/priority-change.d \
./tests/threads/priority-condvar.d \
./tests/threads/priority-donate-chain.d \
./tests/threads/priority-donate-lower.d \
./tests/threads/priority-donate-multiple.d \
./tests/threads/priority-donate-multiple2.d \
./tests/threads/priority-donate-nest.d \
./tests/threads/priority-donate-one.d \
./tests/threads/priority-donate-sema.d \
./tests/threads/priority-fifo.d \
./tests/threads/priority-preempt.d \
./tests/threads/priority-sema.d \
./tests/threads/tests.d 


# Each subdirectory must supply rules for building sources it contributes
tests/threads/%.o: ../tests/threads/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


