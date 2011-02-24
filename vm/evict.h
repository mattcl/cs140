
#ifndef PAGE_H_
#define PAGE_H_
#include <stdint.h>

void evict_init(size_t threshold_set);
void * evict_page(void);
void clear_until_threshold(void);

#endif /* PAGE_H_ */
