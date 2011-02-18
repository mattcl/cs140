################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../threads/init.c \
../threads/interrupt.c \
../threads/malloc.c \
../threads/palloc.c \
../threads/synch.c \
../threads/thread.c 

S_UPPER_SRCS += \
../threads/intr-stubs.S \
../threads/kernel.lds.S \
../threads/loader.S \
../threads/start.S \
../threads/switch.S 

OBJS += \
./threads/init.o \
./threads/interrupt.o \
./threads/intr-stubs.o \
./threads/kernel.lds.o \
./threads/loader.o \
./threads/malloc.o \
./threads/palloc.o \
./threads/start.o \
./threads/switch.o \
./threads/synch.o \
./threads/thread.o 

C_DEPS += \
./threads/init.d \
./threads/interrupt.d \
./threads/malloc.d \
./threads/palloc.d \
./threads/synch.d \
./threads/thread.d 


# Each subdirectory must supply rules for building sources it contributes
threads/%.o: ../threads/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

threads/%.o: ../threads/%.S
	@echo 'Building file: $<'
	@echo 'Invoking: GCC Assembler'
	as  -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


