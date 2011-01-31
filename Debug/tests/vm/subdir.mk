################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/vm/child-inherit.c \
../tests/vm/child-linear.c \
../tests/vm/child-mm-wrt.c \
../tests/vm/child-qsort-mm.c \
../tests/vm/child-qsort.c \
../tests/vm/child-sort.c \
../tests/vm/mmap-bad-fd.c \
../tests/vm/mmap-clean.c \
../tests/vm/mmap-close.c \
../tests/vm/mmap-exit.c \
../tests/vm/mmap-inherit.c \
../tests/vm/mmap-misalign.c \
../tests/vm/mmap-null.c \
../tests/vm/mmap-over-code.c \
../tests/vm/mmap-over-data.c \
../tests/vm/mmap-over-stk.c \
../tests/vm/mmap-overlap.c \
../tests/vm/mmap-read.c \
../tests/vm/mmap-remove.c \
../tests/vm/mmap-shuffle.c \
../tests/vm/mmap-twice.c \
../tests/vm/mmap-unmap.c \
../tests/vm/mmap-write.c \
../tests/vm/mmap-zero.c \
../tests/vm/page-linear.c \
../tests/vm/page-merge-mm.c \
../tests/vm/page-merge-par.c \
../tests/vm/page-merge-seq.c \
../tests/vm/page-merge-stk.c \
../tests/vm/page-parallel.c \
../tests/vm/page-shuffle.c \
../tests/vm/parallel-merge.c \
../tests/vm/pt-bad-addr.c \
../tests/vm/pt-bad-read.c \
../tests/vm/pt-big-stk-obj.c \
../tests/vm/pt-grow-bad.c \
../tests/vm/pt-grow-pusha.c \
../tests/vm/pt-grow-stack.c \
../tests/vm/pt-grow-stk-sc.c \
../tests/vm/pt-write-code-2.c \
../tests/vm/pt-write-code.c \
../tests/vm/qsort.c 

OBJS += \
./tests/vm/child-inherit.o \
./tests/vm/child-linear.o \
./tests/vm/child-mm-wrt.o \
./tests/vm/child-qsort-mm.o \
./tests/vm/child-qsort.o \
./tests/vm/child-sort.o \
./tests/vm/mmap-bad-fd.o \
./tests/vm/mmap-clean.o \
./tests/vm/mmap-close.o \
./tests/vm/mmap-exit.o \
./tests/vm/mmap-inherit.o \
./tests/vm/mmap-misalign.o \
./tests/vm/mmap-null.o \
./tests/vm/mmap-over-code.o \
./tests/vm/mmap-over-data.o \
./tests/vm/mmap-over-stk.o \
./tests/vm/mmap-overlap.o \
./tests/vm/mmap-read.o \
./tests/vm/mmap-remove.o \
./tests/vm/mmap-shuffle.o \
./tests/vm/mmap-twice.o \
./tests/vm/mmap-unmap.o \
./tests/vm/mmap-write.o \
./tests/vm/mmap-zero.o \
./tests/vm/page-linear.o \
./tests/vm/page-merge-mm.o \
./tests/vm/page-merge-par.o \
./tests/vm/page-merge-seq.o \
./tests/vm/page-merge-stk.o \
./tests/vm/page-parallel.o \
./tests/vm/page-shuffle.o \
./tests/vm/parallel-merge.o \
./tests/vm/pt-bad-addr.o \
./tests/vm/pt-bad-read.o \
./tests/vm/pt-big-stk-obj.o \
./tests/vm/pt-grow-bad.o \
./tests/vm/pt-grow-pusha.o \
./tests/vm/pt-grow-stack.o \
./tests/vm/pt-grow-stk-sc.o \
./tests/vm/pt-write-code-2.o \
./tests/vm/pt-write-code.o \
./tests/vm/qsort.o 

C_DEPS += \
./tests/vm/child-inherit.d \
./tests/vm/child-linear.d \
./tests/vm/child-mm-wrt.d \
./tests/vm/child-qsort-mm.d \
./tests/vm/child-qsort.d \
./tests/vm/child-sort.d \
./tests/vm/mmap-bad-fd.d \
./tests/vm/mmap-clean.d \
./tests/vm/mmap-close.d \
./tests/vm/mmap-exit.d \
./tests/vm/mmap-inherit.d \
./tests/vm/mmap-misalign.d \
./tests/vm/mmap-null.d \
./tests/vm/mmap-over-code.d \
./tests/vm/mmap-over-data.d \
./tests/vm/mmap-over-stk.d \
./tests/vm/mmap-overlap.d \
./tests/vm/mmap-read.d \
./tests/vm/mmap-remove.d \
./tests/vm/mmap-shuffle.d \
./tests/vm/mmap-twice.d \
./tests/vm/mmap-unmap.d \
./tests/vm/mmap-write.d \
./tests/vm/mmap-zero.d \
./tests/vm/page-linear.d \
./tests/vm/page-merge-mm.d \
./tests/vm/page-merge-par.d \
./tests/vm/page-merge-seq.d \
./tests/vm/page-merge-stk.d \
./tests/vm/page-parallel.d \
./tests/vm/page-shuffle.d \
./tests/vm/parallel-merge.d \
./tests/vm/pt-bad-addr.d \
./tests/vm/pt-bad-read.d \
./tests/vm/pt-big-stk-obj.d \
./tests/vm/pt-grow-bad.d \
./tests/vm/pt-grow-pusha.d \
./tests/vm/pt-grow-stack.d \
./tests/vm/pt-grow-stk-sc.d \
./tests/vm/pt-write-code-2.d \
./tests/vm/pt-write-code.d \
./tests/vm/qsort.d 


# Each subdirectory must supply rules for building sources it contributes
tests/vm/%.o: ../tests/vm/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


