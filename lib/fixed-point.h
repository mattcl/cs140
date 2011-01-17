/*                                                                                 
 * File: fixed-point.h                                                                     
 * -------------------
 * Implements fixed point operations                                                         
 */


#ifndef __LIB__FIXED_POINT
#define __LIB__FIXED_POINT


#include <stdint.h> //int32_t                                                                

#define INT_FIELD_SIZE 17
#define INT_BITS 32
#define FRAC_FIELD_SIZE 14
#define MAX_INT_CONV_VAL 262143 

#define CONVERSION_VAL (1 << (INT_FIELD_SIZE))
#define CONVERSION_VAL_32 (1 << (INT_BITS))

typedef int32_t fixed_point;

inline fixed_point itof(int n);
inline int ftoi(fixed_point f);
inline fixed_point fp_add(fixed_point f1, fixed_point f2);
inline fixed_point fp_sub(fixed_point f1, fixed_point f2);
inline fixed_point fp_int_add(fixed_point f, int n);
inline fixed_point fp_int_sub(fixed_point f, int n);
inline fixed_point fp_mult(fixed_point f1, fixed_point f2);
inline fixed_point fp_int_mult(fixed_point f, int n);
inline fixed_point fp_div(fixed_point f1, fixed_point f2);
inline fixed_point fp_int_div(fixed_point f, int n);


#endif
