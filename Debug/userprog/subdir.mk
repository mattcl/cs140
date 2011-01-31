################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../userprog/exception.c \
../userprog/gdt.c \
../userprog/pagedir.c \
../userprog/process.c \
../userprog/syscall.c \
../userprog/tss.c 

OBJS += \
./userprog/exception.o \
./userprog/gdt.o \
./userprog/pagedir.o \
./userprog/process.o \
./userprog/syscall.o \
./userprog/tss.o 

C_DEPS += \
./userprog/exception.d \
./userprog/gdt.d \
./userprog/pagedir.d \
./userprog/process.d \
./userprog/syscall.d \
./userprog/tss.d 


# Each subdirectory must supply rules for building sources it contributes
userprog/%.o: ../userprog/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


