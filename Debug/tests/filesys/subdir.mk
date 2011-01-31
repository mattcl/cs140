################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/filesys/seq-test.c 

OBJS += \
./tests/filesys/seq-test.o 

C_DEPS += \
./tests/filesys/seq-test.d 


# Each subdirectory must supply rules for building sources it contributes
tests/filesys/%.o: ../tests/filesys/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


