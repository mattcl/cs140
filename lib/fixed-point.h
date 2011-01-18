/*                                                                                 
 * File: fixed-point.h                                                                     
 * -------------------
 * Implements fixed point operations
 * any functions that take int arguments have are of
 * form fp_int_op(float_point,int)                                                         
 */


#ifndef __LIB__FIXED_POINT
#define __LIB__FIXED_POINT


#include <stdint.h> //int32_t                                                                

#define INT_FIELD_SIZE 17
#define FRAC_FIELD_SIZE 14
#define MAX_INT_CONV_VAL 262143 

#define CONVERSION_VAL (1 << (FRAC_FIELD_SIZE))

/* The fixed_point uses a 32 bit int as it's
 * underlying representation.  1 bit is the signed bit,
 * p bits are determined as the whole number part of the 
 * number, and q bits are used as the fractional part of 
 * the number (were the number is represented as p.q).  
 * For more details consult a reference on floating point 
 * representations.
 */
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
