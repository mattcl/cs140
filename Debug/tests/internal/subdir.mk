################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/internal/list.c \
../tests/internal/stdio.c \
../tests/internal/stdlib.c 

OBJS += \
./tests/internal/list.o \
./tests/internal/stdio.o \
./tests/internal/stdlib.o 

C_DEPS += \
./tests/internal/list.d \
./tests/internal/stdio.d \
./tests/internal/stdlib.d 


# Each subdirectory must supply rules for building sources it contributes
tests/internal/%.o: ../tests/internal/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


