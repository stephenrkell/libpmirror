#ifndef __HEAP_INDEX_H
#define __HEAP_INDEX_H

#include "memtable.h"

struct entry
{
	unsigned present:1;
	unsigned distance:7;
} __attribute__((packed));

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

/* A thread-local variable to override the "caller" arguments. */
extern __thread void *__current_allocsite;

#endif
