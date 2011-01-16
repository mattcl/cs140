/*
 * File: fixed-point.h 
 * -------------------
 * Implements fixed point operations
 */


#ifndef __LIB__FIXED_POINT
#define __LIB__FIXED_POINT

#include <math.h>  // pow
#include <debug.h> // assert

#define INT_FIELD_SIZE 17
#define FRAC_FIELD_SIZE 14

#define CONVERSION_VAL (pow(INT_FIELD_SIZE, 2)) 
#endif /* fixed-point.h */
