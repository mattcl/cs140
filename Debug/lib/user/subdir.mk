################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lib/user/console.c \
../lib/user/debug.c \
../lib/user/entry.c \
../lib/user/syscall.c 

OBJS += \
./lib/user/console.o \
./lib/user/debug.o \
./lib/user/entry.o \
./lib/user/syscall.o 

C_DEPS += \
./lib/user/console.d \
./lib/user/debug.d \
./lib/user/entry.d \
./lib/user/syscall.d 


# Each subdirectory must supply rules for building sources it contributes
lib/user/%.o: ../lib/user/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


