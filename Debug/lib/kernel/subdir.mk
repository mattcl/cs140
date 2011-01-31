################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lib/kernel/bitmap.c \
../lib/kernel/console.c \
../lib/kernel/debug.c \
../lib/kernel/hash.c \
../lib/kernel/list.c 

OBJS += \
./lib/kernel/bitmap.o \
./lib/kernel/console.o \
./lib/kernel/debug.o \
./lib/kernel/hash.o \
./lib/kernel/list.o 

C_DEPS += \
./lib/kernel/bitmap.d \
./lib/kernel/console.d \
./lib/kernel/debug.d \
./lib/kernel/hash.d \
./lib/kernel/list.d 


# Each subdirectory must supply rules for building sources it contributes
lib/kernel/%.o: ../lib/kernel/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


