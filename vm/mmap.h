#ifndef MMAP_H_
#define MMAP_H_

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <hash.h>
#include <debug.h>

void mmap_save_all(struct mmap_hash_entry *entry);
bool mmap_read_in(void *faulting_addr);
bool mmap_write_out(struct process *cur_process, uint32_t *pd,
		pid_t pid, void *uaddr, void *kaddr);
struct mmap_hash_entry *uaddr_to_mmap_entry(struct process *cur, void *uaddr);
struct mmap_hash_entry *mapid_to_hash_entry(mapid_t mid);

unsigned mmap_hash_func (const struct hash_elem *a, void *aux UNUSED);
bool mmap_hash_compare  (const struct hash_elem *a,
		const struct hash_elem *b, void *aux UNUSED);
void mmap_hash_entry_destroy (struct hash_elem *e, void *aux UNUSED);

#endif /* MMAP_H_ */
