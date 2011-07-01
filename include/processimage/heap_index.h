#ifndef __HEAP_INDEX_H
#define __HEAP_INDEX_H

#include "memtable.h"

struct entry
{
	unsigned present:1;
	unsigned distance:7;
} __attribute__((packed));

struct trailer
{
	const void *alloc_site;
	struct entry next;
	struct entry prev;

} __attribute__((packed));


struct trailer *lookup_object_info(void *mem, void **out_object_start);

#endif
