/*
 * File: fixed-point.c
 * --------------------
 * implements fixed_point operations.  Includes asserts to prevent 
 * conversions of numbers to big or small
 */

#include <assert.h>
#include <stdint.h>

inline fixed_point itof(int n){
  assert(n <= MAX_INT_CONV_VAL);
  return n * CONVERSION_VAL;
}

inline int ftoi(fixed_point f){
  return f / CONVERSION_VAL;
}

inline fixed_point fp_add(fixed_point f1, fixed_point f2){
  return f1 + f2;
}

inline fixed_point fp_subtract(fixed_point f1, fixed_point f2){
  return f1 - f2;
}

inline fixed_point fp_int_add(fixed_point f, int n){
  return f + i_to_f(n);
}

inline fixed_point fp_int_sub(fixed_point f, int n){
  return f - i_to_f(n);
}

inline fixed_point fp_mult(fixed_point f1, fixed_point f2){
  return (((int64_t f1) * f2) / CONVERSION_VAL);
}

inline fixed_point fp_int_mult(fixed_point f, int n){
  return f * n;
}

inline fixed_point fp_div(fixed_point f1, fixed_point f2){
  return (((int64_t f1) * (CONVERSION_VAL)) / f2);
}

inline fixed_point fp_int_div(fixed_point f, int n){
  return f / n;
}

/*
void conversion_tests(void) {
  int n = 5555555;
  assert(n < MAX_INT_CONV_VAL);
  fixed_point f = INT_TO_FP(n);
  int n2 = FP_TO_INT(f);
  assert(n == n2);
}

int main(const int argc, const char* argv[]) {
  conversion_tests();
}
*/


//#endif /* fixed-point.h */

