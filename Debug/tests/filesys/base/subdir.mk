################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/filesys/base/child-syn-read.c \
../tests/filesys/base/child-syn-wrt.c \
../tests/filesys/base/lg-create.c \
../tests/filesys/base/lg-full.c \
../tests/filesys/base/lg-random.c \
../tests/filesys/base/lg-seq-block.c \
../tests/filesys/base/lg-seq-random.c \
../tests/filesys/base/sm-create.c \
../tests/filesys/base/sm-full.c \
../tests/filesys/base/sm-random.c \
../tests/filesys/base/sm-seq-block.c \
../tests/filesys/base/sm-seq-random.c \
../tests/filesys/base/syn-read.c \
../tests/filesys/base/syn-remove.c \
../tests/filesys/base/syn-write.c 

OBJS += \
./tests/filesys/base/child-syn-read.o \
./tests/filesys/base/child-syn-wrt.o \
./tests/filesys/base/lg-create.o \
./tests/filesys/base/lg-full.o \
./tests/filesys/base/lg-random.o \
./tests/filesys/base/lg-seq-block.o \
./tests/filesys/base/lg-seq-random.o \
./tests/filesys/base/sm-create.o \
./tests/filesys/base/sm-full.o \
./tests/filesys/base/sm-random.o \
./tests/filesys/base/sm-seq-block.o \
./tests/filesys/base/sm-seq-random.o \
./tests/filesys/base/syn-read.o \
./tests/filesys/base/syn-remove.o \
./tests/filesys/base/syn-write.o 

C_DEPS += \
./tests/filesys/base/child-syn-read.d \
./tests/filesys/base/child-syn-wrt.d \
./tests/filesys/base/lg-create.d \
./tests/filesys/base/lg-full.d \
./tests/filesys/base/lg-random.d \
./tests/filesys/base/lg-seq-block.d \
./tests/filesys/base/lg-seq-random.d \
./tests/filesys/base/sm-create.d \
./tests/filesys/base/sm-full.d \
./tests/filesys/base/sm-random.d \
./tests/filesys/base/sm-seq-block.d \
./tests/filesys/base/sm-seq-random.d \
./tests/filesys/base/syn-read.d \
./tests/filesys/base/syn-remove.d \
./tests/filesys/base/syn-write.d 


# Each subdirectory must supply rules for building sources it contributes
tests/filesys/base/%.o: ../tests/filesys/base/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


