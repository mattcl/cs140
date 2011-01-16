/*
 * File: fixed-point.h 
 * -------------------
 * Implements fixed point operations
 */


#ifndef __LIB__FIXED_POINT
#define __LIB__FIXED_POINT

//#include <math.h>  // pow
#include <debug.h> // assert
#include <stdint.h> //int32_t

#define INT_FIELD_SIZE 17
#define FRAC_FIELD_SIZE 14

#define CONVERSION_VAL (1 << (INT_FIELD_SIZE))



typedef int32_t fixed_point; 


#define itof(n) ((n) * (CONVERSION_VAL))
#define ftoi(f) ((n) / (CONVERSION_VAL))
#define FP_ADD(f1, f2) ((f1)+(f2))
#define FP_SUB(f1, f2) ((f1) -(f2))
#define FP_INT_ADD(f,n) ((f) + (itof(n)))
#define FP_INT_SUBTRACT(f, n) ((f) - (itof(n)))
#define FP_MULT(f1,f2) (((int64_t (f1)) * (f2))/CONVERSION_VAL)
#define FP_INT_MULT(f,n) ((f) * (n))
#define FP_DIV(f1, f2) (((int64_t (f1)) * (CONVERSION_VAL)) / (f2))
#define FP_INT_DIV(f, n) ( (f) / (n) )





#endif /* fixed-point.h */
