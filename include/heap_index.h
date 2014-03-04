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
#if defined(__x86_64__) || defined(x86_64)
#define ADDR_BITSIZE 48
#else
#define ADDR_BITSIZE WORD_BITSIZE
#endif
struct insert
{
	unsigned alloc_site_flag:1;
	unsigned long alloc_site:(ADDR_BITSIZE-1);
#ifdef HEAP_INDEX_HEADER_INCLUDE
#include HEAP_INDEX_HEADER_INCLUDE
#endif
	struct entry next;
	struct entry prev;

} __attribute__((packed));

/* As well as the index of 'entry' objects for l1 allocations, we also define a 
 * separate, more flexible structure for regions which contain l2 and deeper
 * allocations. If a region contains such, its index entry will have 
 * .present == 0 and .removed == 1, and we keep a linked list of these entries. 
 * Since the list is not heap-threaded, the start of the list has to be kept
 * in a separate map, keyed on the base address of the 512-byte region that
 * is indexed. (TODO: keyed how? can we exploit the 'distance' field somehow?
 * As a set-associativity construct?) NOTE: we *don't* want to malloc-allocate
 * the lists, because that will risk infinite regression or at least reentrancy
 * issues: malloc triggering malloc. (It will probably stabilise, since not
 * every malloc will trigger a malloc. BUT a simple NORESERVE mapped region
 * and open hashing seems the best bet...no? */
struct deep_entry
{
	// initial small fields point to the object and describe the allocation
	unsigned distance_4bytes:32;  // offset of the indexed object in fourbytes from the region base, up to 16GB
	unsigned level_minus_one:2;      // allocation level of this object *minus one*, i.e. 1..4
	unsigned valid:1;

	unsigned size_4bytes:24; // byte size in multiples of four bytes -- v. large is very unlikely for nested allocations
	                       // (BUT this table has to hold l1 allocations that overlap too! 
	                       // -- but only below malloc's mmap threshold though, at most 64MB)
	struct insert ins; // so we can pass its address out of lookup_object_info
};
struct deep_entry_region
{
	struct deep_entry *region;
	void *base_addr; // beginning of the covered range
	void *end_addr;  // one past the end of the covered range
	int undersize_right_shift;
	size_t half_size;
};

/* We also use a set of coarser memtable-alikes to map deeper entries. 
 * They tend to be very object-dense 
 * but span limited areas (with of a few MB). What's a good fit for this?
 * What do we need to remember for each allocation? 
 * Can we use bitmaps? "object starts here" per word?
 * A page's worth of bits, i.e. 32768 bits, would encode 256KB in 8-byte words. 
 * HMM. That's not great... a 1-to-64 memtable. THEN we need another table to
 * hold the object info
 * */
extern struct deep_entry_region deep_entry_regions[1u<<6]; // must match the bit size of "distance"!

void __index_deep_alloc(void *ptr, int level, unsigned size_bytes) __attribute__((weak));
void __unindex_deep_alloc(void *ptr, int level) __attribute__((weak));
// most users shouldn't need this API -- it's for testing
struct deep_entry *__lookup_deep_alloc(void *ptr, int level_upper_bound, int level_lower_bound, 
		struct deep_entry_region **out_region) __attribute__((weak));

struct insert *lookup_object_info(const void *mem, void **out_object_start) __attribute__((weak));

/* A thread-local variable to override the "caller" arguments. 
 * Platforms without TLS have to do without this feature. */
#ifndef NO_TLS
extern __thread void *__current_allocsite;
extern __thread void *__current_allocfn;
extern __thread size_t __current_allocsz;
extern __thread int __current_alloclevel;
#else
#warning "Using thread-unsafe __current_allocsite variable."
extern void *__current_allocsite;
extern void *__current_allocfn;
extern size_t __current_allocsz;
extern int __current_alloclevel;
#endif

#endif
