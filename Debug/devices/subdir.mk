################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../devices/block.c \
../devices/ide.c \
../devices/input.c \
../devices/intq.c \
../devices/kbd.c \
../devices/partition.c \
../devices/pit.c \
../devices/rtc.c \
../devices/serial.c \
../devices/shutdown.c \
../devices/speaker.c \
../devices/timer.c \
../devices/vga.c 

OBJS += \
./devices/block.o \
./devices/ide.o \
./devices/input.o \
./devices/intq.o \
./devices/kbd.o \
./devices/partition.o \
./devices/pit.o \
./devices/rtc.o \
./devices/serial.o \
./devices/shutdown.o \
./devices/speaker.o \
./devices/timer.o \
./devices/vga.o 

C_DEPS += \
./devices/block.d \
./devices/ide.d \
./devices/input.d \
./devices/intq.d \
./devices/kbd.d \
./devices/partition.d \
./devices/pit.d \
./devices/rtc.d \
./devices/serial.d \
./devices/shutdown.d \
./devices/speaker.d \
./devices/timer.d \
./devices/vga.d 


# Each subdirectory must supply rules for building sources it contributes
devices/%.o: ../devices/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


