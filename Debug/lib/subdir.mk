################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../lib/arithmetic.c \
../lib/debug.c \
../lib/random.c \
../lib/stdio.c \
../lib/stdlib.c \
../lib/string.c \
../lib/ustar.c 

OBJS += \
./lib/arithmetic.o \
./lib/debug.o \
./lib/random.o \
./lib/stdio.o \
./lib/stdlib.o \
./lib/string.o \
./lib/ustar.o 

C_DEPS += \
./lib/arithmetic.d \
./lib/debug.d \
./lib/random.d \
./lib/stdio.d \
./lib/stdlib.d \
./lib/string.d \
./lib/ustar.d 


# Each subdirectory must supply rules for building sources it contributes
lib/%.o: ../lib/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


