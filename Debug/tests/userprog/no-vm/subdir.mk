################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/userprog/no-vm/multi-oom.c 

OBJS += \
./tests/userprog/no-vm/multi-oom.o 

C_DEPS += \
./tests/userprog/no-vm/multi-oom.d 


# Each subdirectory must supply rules for building sources it contributes
tests/userprog/no-vm/%.o: ../tests/userprog/no-vm/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


