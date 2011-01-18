/*
 * File: fixed-point.c
 * --------------------
 * implements fixed_point operations.  Includes asserts to prevent 
 * conversions of numbers to big or small
 */

#include <stdint.h>
#include <debug.h>
#include "fixed-point.h"

#define MAX_INT_CONV_VAL 262143 

/* the conversion value "f" = 2^14
 * It is based on p=17, q=14, and 1 bit 
 * for a sign in a 32 bit integeer
 * if this is changed MAX_INT_COV_VAL must also
 * be changed
 */
#define CONVERSION_VAL (16384)


/* multiplying n by CONVERSION_VAL shifts to the 
 * left by q bits while preserving the sign bit
 */
inline fixed_point itof(int n){
  return n * CONVERSION_VAL;
}

/* dividing n by CONVERSION_VAL bits shifts n to the
 * right by q bits while preserving the sign bit.
 */
inline int ftoi(fixed_point f){
  return f / CONVERSION_VAL;
}

/* since both numbers are represented the same way
 * we just do normal binary addition and their values
 * will be preserved
 */
inline fixed_point fp_add(fixed_point f1, fixed_point f2){
  return f1 + f2;
}

/* we just perform ordinary binary subtraction */
inline fixed_point fp_sub(fixed_point f1, fixed_point f2){
  return f1 - f2;
}

/* we want to add int and a fixed_point, so we convert
 * the int first
 */
inline fixed_point fp_int_add(fixed_point f, int n){
  return f + itof(n);
}

/* we convert the int then do the subtraction */
inline fixed_point fp_int_sub(fixed_point f, int n){
  return f - itof(n);
}

/* when we multiply two fixed_point's we may have
 * an overflow, so we cast to a 64 bit int to catch the 
 * the overflow, then we bit shift q bits to the right
 * to account for the fact that we have moved the decimal
 * point.  For more information please consult a reference
 * on floating point multiplication.
 */
inline fixed_point fp_mult(fixed_point f1, fixed_point f2){
  ASSERT(CONVERSION_VAL != 0);
  return ((((int64_t) f1) * f2) / CONVERSION_VAL);
}

/* since we only have one floating point we won't move the 
 * decimal nor do we have to worry about overflow
 */
inline fixed_point fp_int_mult(fixed_point f, int n){
  return f * n;
}

/* see fp_mult */
inline fixed_point fp_div(fixed_point f1, fixed_point f2){
  return ((int64_t) f1 * CONVERSION_VAL) / (f2);
}

/* see fp_int_div */
inline fixed_point fp_int_div(fixed_point f, int n){
  return f / n;
}


