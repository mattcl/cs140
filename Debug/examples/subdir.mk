################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../examples/bubsort.c \
../examples/cat.c \
../examples/cmp.c \
../examples/cp.c \
../examples/echo.c \
../examples/halt.c \
../examples/hex-dump.c \
../examples/insult.c \
../examples/lineup.c \
../examples/ls.c \
../examples/matmult.c \
../examples/mcat.c \
../examples/mcp.c \
../examples/mkdir.c \
../examples/pwd.c \
../examples/recursor.c \
../examples/rm.c \
../examples/shell.c 

OBJS += \
./examples/bubsort.o \
./examples/cat.o \
./examples/cmp.o \
./examples/cp.o \
./examples/echo.o \
./examples/halt.o \
./examples/hex-dump.o \
./examples/insult.o \
./examples/lineup.o \
./examples/ls.o \
./examples/matmult.o \
./examples/mcat.o \
./examples/mcp.o \
./examples/mkdir.o \
./examples/pwd.o \
./examples/recursor.o \
./examples/rm.o \
./examples/shell.o 

C_DEPS += \
./examples/bubsort.d \
./examples/cat.d \
./examples/cmp.d \
./examples/cp.d \
./examples/echo.d \
./examples/halt.d \
./examples/hex-dump.d \
./examples/insult.d \
./examples/lineup.d \
./examples/ls.d \
./examples/matmult.d \
./examples/mcat.d \
./examples/mcp.d \
./examples/mkdir.d \
./examples/pwd.d \
./examples/recursor.d \
./examples/rm.d \
./examples/shell.d 


# Each subdirectory must supply rules for building sources it contributes
examples/%.o: ../examples/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


