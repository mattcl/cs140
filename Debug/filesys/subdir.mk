################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../filesys/directory.c \
../filesys/file.c \
../filesys/filesys.c \
../filesys/free-map.c \
../filesys/fsutil.c \
../filesys/inode.c 

OBJS += \
./filesys/directory.o \
./filesys/file.o \
./filesys/filesys.o \
./filesys/free-map.o \
./filesys/fsutil.o \
./filesys/inode.o 

C_DEPS += \
./filesys/directory.d \
./filesys/file.d \
./filesys/filesys.d \
./filesys/free-map.d \
./filesys/fsutil.d \
./filesys/inode.d 


# Each subdirectory must supply rules for building sources it contributes
filesys/%.o: ../filesys/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


