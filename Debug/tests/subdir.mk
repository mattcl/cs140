################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/arc4.c \
../tests/cksum.c \
../tests/lib.c \
../tests/main.c 

OBJS += \
./tests/arc4.o \
./tests/cksum.o \
./tests/lib.o \
./tests/main.o 

C_DEPS += \
./tests/arc4.d \
./tests/cksum.d \
./tests/lib.d \
./tests/main.d 


# Each subdirectory must supply rules for building sources it contributes
tests/%.o: ../tests/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


