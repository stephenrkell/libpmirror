#ifndef __HEAP_INDEX_H
#define __HEAP_INDEX_H

#include "memtable.h"

struct entry
{
	unsigned present:1;
	unsigned removed:1;  /* whether this link is in the "removed" state in Harris's algorithm */
	unsigned distance:6; /* distance from the base of this entry's region, in 8-byte units */
} __attribute__((packed));

#define DISTANCE_UNIT_SHIFT 3
/* NOTE: make sure that "distance" is wide enough to store offsets up to
 * entry_size_in_bytes bytes long! */

extern struct entry *index_region __attribute__((weak));

#define WORD_BITSIZE ((sizeof (void*))<<3)
struct trailer
{
	unsigned alloc_site_flag:1;
	unsigned long alloc_site:(WORD_BITSIZE-1);
#ifdef HEAP_INDEX_TRAILER_INCLUDE
#include HEAP_INDEX_TRAILER_INCLUDE
#endif
	struct entry next;
	struct entry prev;

} __attribute__((packed));


struct trailer *lookup_object_info(const void *mem, void **out_object_start) __attribute__((weak));

/* A thread-local variable to override the "caller" arguments. 
 * Platforms without TLS have to do without this feature. */
#ifndef NO_TLS
extern __thread void *__current_allocsite;
#else
#warning "Compiling without __current_allocsite TLS variable."                  
#define __current_allocsite ((void*)0)                                          
#endif

#endif
