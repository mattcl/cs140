#include "uint_set.h"
#include "threads/malloc.h"


static unsigned int_set_hash_func(const struct hash_elem*a, void *aux UNUSED){
	uint32_t key = hash_entry(a, struct uint_set_entry, e)->key;
	return hash_bytes(&key, (sizeof(uint32_t)));
}

static bool int_set_hash_comp(const struct hash_elem *a,
							  const struct hash_elem *b, void *aux UNUSED){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct uint_set_entry, e)->key <
			hash_entry(a, struct uint_set_entry, e)->key);
}

static void int_set_hash_destroy(struct hash_elem *e, void *aux UNUSED){
	free(hash_entry(e, struct uint_set_entry, e));
}

bool uint_set_init(struct uint_set *set){
	return hash_init(&set->set_hash, &int_set_hash_func, &int_set_hash_comp, NULL);
}

bool uint_set_is_member(struct uint_set *set, uint32_t key){
	struct uint_set_entry entry;
	entry.key = key;
	struct hash_elem *res = hash_find(&set->set_hash, &entry.e);
	if(res != NULL){
		return true;
	}else{
		return false;
	}
}

void uint_set_add_member(struct uint_set *set, uint32_t key){
	if(!uint_set_is_member(set, key)){
		struct uint_set_entry *e = calloc(1, sizeof(struct uint_set_entry));
		e->key = key;
		hash_insert(&set->set_hash, &e->e);
	}
}

void uint_set_remove(struct uint_set *set, uint32_t key){
	struct uint_set_entry entry;
	entry.key = key;
	struct hash_elem *del = hash_delete(&set->set_hash, &entry.e);
	if(del != NULL){
		free(hash_entry(del, struct uint_set_entry, e));
	}
}

void uint_set_destroy(struct uint_set *set){
	hash_destroy(&set->set_hash, &int_set_hash_destroy);
}

void uint_set_print_all(struct uint_set *set){
	struct hash_iterator iter;
	hash_first(&iter, &set->set_hash);
	struct hash_elem * elem;
	while (hash_next (&iter)){
		struct uint_set_entry *entry = hash_entry (hash_cur (&iter),
				struct uint_set_entry, e);
		printf("entry->key %u\n",entry->key);
	}
}



