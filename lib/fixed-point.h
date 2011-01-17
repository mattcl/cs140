/*                                                                                 
 * File: fixed-point.h                                                                     
 * -------------------
 * Implements fixed point operations                                                         
 */


#ifndef __LIB__FIXED_POINT
#define __LIB__FIXED_POINT


#include <stdint.h> //int32_t                                                                

#define INT_FIELD_SIZE 17
#define FRAC_FIELD_SIZE 14
#define MAX_INT_CONV_VAL 262143 

#define CONVERSION_VAL (1 << (INT_FIELD_SIZE))

typedef int32_t fixed_point;

inline fixed_point itof(int n);
inline int ftoi(fixed_point f);
inline fixed_point fp_add(fixed_point f1, fixed_point f2);
inline fixed_point fp_subtract(fixed_point f1, fixed_point f2);
inline fixed_point fp_int_add(fixed_point f, int n);
inline fixed_point fp_int_sub(fixed_point f, int n);
inline fixed_point fp_mult(fixed_point f1, fixed_point f2);
inline fixed_point fp_int_mult(fixed_point f, int n);
inline fixed_point fp_div(fixed_point f1, fixed_point f2);
inline fixed_point fp_int_div(fixed_point f, int n);



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
