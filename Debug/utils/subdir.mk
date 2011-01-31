################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../utils/setitimer-helper.c \
../utils/squish-pty.c \
../utils/squish-unix.c 

OBJS += \
./utils/setitimer-helper.o \
./utils/squish-pty.o \
./utils/squish-unix.o 

C_DEPS += \
./utils/setitimer-helper.d \
./utils/squish-pty.d \
./utils/squish-unix.d 


# Each subdirectory must supply rules for building sources it contributes
utils/%.o: ../utils/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


