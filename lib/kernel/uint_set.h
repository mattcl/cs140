#ifndef INT_SET_H_
#define INT_SET_H_

/* I really just want a set damn it */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "hash.h"
#include "../debug.h"

struct uint_set{
	struct hash set_hash;
};

struct uint_set_entry{
	uint32_t key;
	struct hash_elem e;
};

bool uint_set_init(struct uint_set *set);

bool uint_set_is_member(struct uint_set *set, uint32_t key);

void uint_set_add_member(struct uint_set *set, uint32_t key);

void uint_set_remove(struct uint_set *set, uint32_t key);

void uint_set_destroy(struct uint_set *set);

void uint_set_print_all(struct uint_set *set);

#endif /* INT_SET_H_ */
