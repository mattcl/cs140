
#ifndef PAGE_H_
#define PAGE_H_
#include <stdint.h>
#include <stddef.h>

void evict_init(size_t threshold_set);
void * evict_page(void *uaddr);
void clear_until_threshold(void);

#endif /* PAGE_H_ */
