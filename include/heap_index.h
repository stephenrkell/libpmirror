#ifndef __HEAP_INDEX_H
#define __HEAP_INDEX_H

#include "memtable.h"

struct entry
{
	unsigned present:1;
	unsigned distance:7;
} __attribute__((packed));

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
