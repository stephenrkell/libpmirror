/* This set of hook definitions will maintain a memtable of all
 * allocated heap chunks, and will store a "trailer" in each chunk
 * tracking its allocation site. 
 *
 * Compile in C99 mode! We use raw "inline" and possibly other C99 things.
 *
 * For the fastest code, compile -O3 and -DNDEBUG. */

/* 
 * TODO:
 * some sort of thread safety
 * use headers, not trailers, to reduce changes of overrun bugs corrupting data
 * produce allocator-specific versions (dlmalloc, initially) that 
 * - don't need trailers...
 * - ... by stealing bits from the host allocator's "size" field (64-bit only)
 * keep chunk lists sorted within each bin?
 */

/* This file uses GNU C extensions */
#define _GNU_SOURCE 

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* We use a memtable -- implemented by some C99 static inline functions */
#include "memtable.h"

/* This defines core hooks, and static prototypes for our hooks. */
#include "malloc_hooks.c" 

struct entry
{
	unsigned present:1;
	unsigned distance:7;
} __attribute__((packed));

struct entry *index_region;
void *index_max_address;

struct trailer
{
	const void *alloc_site;
	struct entry next;
	struct entry prev;

	/* How to make this structure fit in reclaimed space:
	 * 
	 * TCmalloc has "a large object size (> 32K) is rounded up to a page size"
	 * -- so if chunks are 8byte-aligned, we need 15-3 bits for the non-pagesize case,
	 *    and 16 bits should also do for the pagesize case (maximum alloc 65535 * 4K == 256MB?)
	 *    so 16 size bits are sufficient, plus one to distinguish the cases,
	 *    or we could do "superpage alignment" for bigger allocs still?
	 *    i.e. two state bits, 12 size bits 
	 *    OR better, split the state bits: 0-prefixed means next 12 bits are byte-size>>3
	 *                                    10-prefixed means next 11 bits are page-size
	 *                                    11-prefixed means next 11 bits are superpage-size
	 * -- this fits the size field in 13 bits total, plus one or two size-bits already stolen
	 *
	 * Since we can encode chunk size in 13 bits, and size is one word, we have
	 * 18 bits spare on 32-bit platforms (assuming one bit already stolen) -- not enough
	 * 50 bits spare on 64-bit platforms (assuming one bit already stolen) -- plenty
	 *
	 * next and prev are already 8 bits each (16 bits in all)
	 * alloc_site can be encoded as {text-segment-id, offset}
	 * where at most 127 text segments may be loaded, say (7 bits),
	 * and each has a maximum size of 32MB, say (25 bits)
	 * -- actually, since we have 50 bits to play with, bump these up to 255 and 64MB
	 *
	 * HMM. Can we fix the 32-bit case by only keeping a singly-linked chunk list?
	 * Using slightly stingier limits on chunk size, text-segment-count and size,
	 * we can:
	 * 0-prefixed means next 9 bits are byte-size>>3        (4KB  > size >= 0)
	 * 10-prefixed means next 8 bits are page-size    (255 * 4KB >= size >= 4KB)
	 * 11-prefix means next 8 bits are superpage-size (255 * 4MB >= size >= 4MB)
	 * PROBLEM: gap in size! need to tweak these bit values to cover sizes in range 1MB--4MB
	 * But supposing we can fit size in 10 bits,
	 * we have 22 bits for trailer fields,
	 * so 14 bits for text-seg and offset;
	 * Not enough!  Need an extra level of indirection...
	 * We'd have to scan malloc-call-sites and give each a unique index.
	 * 
	 * Means on a 64-bit allocator we can fit all our metadata (48--50 bits) in stolen bits!
	 * BUT we pay some overhead in wasted space from rounding up to page/superpage sizes
	 * -- can collect empirical evidence that non-page-multiple large malloc()s are rare.
	 *
	 * HMM. Can we fix the 32-bit case by only keeping a singly-linked chunk list?
	 * Using slightly stingier limits on chunk size, text-segment-count and size,
	 * perhaps:
	 * 0-prefixed means next 9 bits are byte-size>>3        (4KB  > size >= 0)
	 * 10-prefixed means next 8 bits are page-size    (255 * 4KB >= size >= 4KB)
	 * 11-prefix means next 8 bits are superpage-size (255 * 4MB >= size >= 4MB)
	 * PROBLEM: gap in size! need to tweak these bit values to cover sizes in range 1MB--4MB
	 * But supposing we can fit size in 10 bits,
	 * we have 22 bits for trailer fields,
	 * so 14 bits for text-seg and offset;
	 * Not enough!  Need an extra level of indirection...
	 * We'd have to scan malloc-call-sites and give each a unique index.
	 */ 

} __attribute__((packed));

#define entry_coverage_in_bytes 1024
typedef struct entry entry_type;
void *index_begin_addr;
void *index_end_addr;

/* "Distance" is a right-shifted offset within a memory region. */
static inline ptrdiff_t entry_to_offset(struct entry e) 
{ 
	assert(e.present); 
	return e.distance << 3; 
}
static inline struct entry offset_to_entry(ptrdiff_t o) 
{ 
	return (struct entry) { .present = 1, .distance = o >> 3 }; 
}
static inline void *entry_ptr_to_addr(struct entry *p_e)
{
	if (!p_e->present) return NULL;
	return MEMTABLE_ENTRY_RANGE_BASE_WITH_TYPE(
		index_region,
		entry_type,
		entry_coverage_in_bytes,
		index_begin_addr,
		index_end_addr,
		p_e)
	+ entry_to_offset(*p_e);
}
static inline void *entry_to_same_range_addr(struct entry e, void *same_range_ptr)
{
	if (!e.present) return NULL;
	return MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(
		index_region,
		entry_type,
		entry_coverage_in_bytes,
		index_begin_addr,
		index_end_addr,
		same_range_ptr) + entry_to_offset(e);
}
static inline struct entry addr_to_entry(void *a)
{
	if (a == NULL) return (struct entry) { .present = 0, .distance = 0 };
	else return offset_to_entry(
		MEMTABLE_ADDR_RANGE_OFFSET_WITH_TYPE(
			index_region, entry_type, entry_coverage_in_bytes, 
			index_begin_addr, index_end_addr,
			a
		)
	);
}

/* The (unsigned) -1 conversion here provokes a compiler warning,
 * which we suppress. There are two ways of doing this.
 * One is to turn the warning off and back on again, clobbering the former setting.
 * Another is, if the GCC version we have allows it (must be > 4.6ish),
 * to use the push/pop mechanism. If we can't pop, we leave it "on" (conservative).
 * To handle the case where we don't have push/pop, 
 * we also suppress pragma warnings, then re-enable them. :-) */
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverflow"
static void check_shift_logic(void)
{
	assert(
			entry_to_offset((struct entry){ .present = 1, .distance = (unsigned) -1})
			+ entry_to_offset((struct entry){ .present = 1, .distance = 1 }) 
		== entry_coverage_in_bytes);
}
/* First, re-enable the overflow pragma, to be conservative. */
#pragma GCC diagnostic warning "-Woverflow"
/* Now, if we have "pop", we will restore it to its actual former setting. */
#pragma GCC diagnostic pop
#pragma GCC diagnostic warning "-Wpragmas"

static void
init_hook(void)
{
	/* Check we got the shift logic correct in entry_to_offset. */
	check_shift_logic();

	if (index_region) return; /* already done */
	
	/* Use a memtable with one byte per 1024B (1KB) of memory. */
	index_begin_addr = (void*) 0U;
	index_end_addr = (void*) 0U;
	
	size_t mapping_size = MEMTABLE_MAPPING_SIZE_WITH_TYPE(unsigned char,
		entry_coverage_in_bytes, 0, 0 /* both 0 => cover full address range */);

	if (mapping_size > BIGGEST_MMAP_ALLOWED)
	{
#ifndef NDEBUG
		fprintf(stderr, "%s: warning: mapping %lld bytes not %ld\n",
			__FILE__, BIGGEST_MMAP_ALLOWED, mapping_size);
		fprintf(stderr, "%s: warning: only bottom 1/%lld of address space is tracked.\n",
			__FILE__, mapping_size / BIGGEST_MMAP_ALLOWED);
#endif
		mapping_size = BIGGEST_MMAP_ALLOWED;
		/* Back-calculate what address range we can cover from this mapping size. */
		unsigned long long nentries = mapping_size / sizeof (entry_type);
		void *one_past_max_indexed_address = index_begin_addr +
			nentries * entry_coverage_in_bytes;
		index_end_addr = one_past_max_indexed_address;
	}
	
	index_region = MEMTABLE_NEW_WITH_TYPE(unsigned char, 
		entry_coverage_in_bytes, index_begin_addr, index_end_addr);
	assert(index_region != MAP_FAILED);
}

static inline struct trailer *trailer_for_chunk(void *addr)
{
	return (struct trailer*) ((char*) addr + malloc_usable_size(addr)) - 1;
}
static inline struct trailer *trailer_for_chunk_with_usable_size(void *addr, size_t usable_size)
{
	return (struct trailer*) ((char*) addr + usable_size) - 1;
}

#ifndef NDEBUG
/* In this newer, more space-compact implementation, we can't do as much
 * sanity checking. Check that if our entry is not present, our distance
 * is 0. */
#define TRAILER_SANITY_CHECK(p_t) assert( \
	!(!((p_t)->next.present) && (p_t)->next.distance != 0) \
	&& !(!((p_t)->prev.present) && (p_t)->prev.distance != 0))

static void list_sanity_check(entry_type *head)
{
	void *cur_chunk = entry_ptr_to_addr(head);
	while (cur_chunk != NULL)
	{
		TRAILER_SANITY_CHECK(trailer_for_chunk(cur_chunk));
		cur_chunk = entry_to_same_range_addr(trailer_for_chunk(cur_chunk)->next, cur_chunk);
	}
}
#else /* NDEBUG */
#define TRAILER_SANITY_CHECK(p_t)
static void list_sanity_check(entry_type *head) {}
#endif

#define INDEX_LOC_FOR_ADDR(a) MEMTABLE_ADDR_WITH_TYPE(index_region, entry_type, \
		entry_coverage_in_bytes, \
		index_begin_addr, index_end_addr, (a))

static void 
index_insert(void *new_chunkaddr, size_t modified_size, const void *caller)
{
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!index_region) init_hook();
	
	/* The address *must* be in our tracked range. Assert this. */
	assert(new_chunkaddr <= index_end_addr);

	/* DEBUGGING: sanity check entire bin */
	list_sanity_check(INDEX_LOC_FOR_ADDR(new_chunkaddr));

	void *head_chunkptr = entry_ptr_to_addr(INDEX_LOC_FOR_ADDR(new_chunkaddr));
	
	/* Populate our extra fields */
	struct trailer *p_trailer = trailer_for_chunk(new_chunkaddr);
	p_trailer->alloc_site = caller;

	/* Add it to the index. We always add to the start of the list, for now. */
	/* 1. Initialize our trailer. */
	p_trailer->next = addr_to_entry(head_chunkptr);
	p_trailer->prev = addr_to_entry(NULL);
	/* 2. Fix up the next trailer, if there is one */
	if (p_trailer->next.present)
	{
		trailer_for_chunk(entry_to_same_range_addr(p_trailer->next, new_chunkaddr))->prev
		 = addr_to_entry(new_chunkaddr);
	}
	/* 3. Fix up the index. */
	*INDEX_LOC_FOR_ADDR(new_chunkaddr) = addr_to_entry(new_chunkaddr); // FIXME: thread-safety
	
	/* sanity check */
	TRAILER_SANITY_CHECK(p_trailer);
	if (p_trailer->next.present) TRAILER_SANITY_CHECK(
		trailer_for_chunk(entry_to_same_range_addr(p_trailer->next, new_chunkaddr)));
	if (p_trailer->prev.present) TRAILER_SANITY_CHECK(
		trailer_for_chunk(entry_to_same_range_addr(p_trailer->prev, new_chunkaddr)));
	list_sanity_check(INDEX_LOC_FOR_ADDR(new_chunkaddr));
}

static void 
post_successful_alloc(void *begin, size_t modified_size, const void *caller)
{
	index_insert(begin, modified_size, caller);
}	

static void pre_alloc(size_t *p_size, const void *caller)
{
	/* We increase the size 
	 * by the amount of extra data we store. 
	 * We later use malloc_usable_size to work out where to store our data. */

	*p_size += sizeof (struct trailer);
}
static void index_delete(void *ptr, size_t freed_usable_size)
{
	/* The freed_usable_size is not strictly necessary. It was added
	 * for handling realloc after-the-fact. In this case, by the time we
	 * get called, the usable size has already changed. However, after-the-fact
	 * is a broken way to handle realloc(), because in the case of a *smaller*
	 * realloc'd size, where the realloc happens in-place, realloc() will overwrite
	 * our trailer with its own (regular heap metadata) trailer, breaking the list.
	 */

	TRAILER_SANITY_CHECK(trailer_for_chunk_with_usable_size(ptr, freed_usable_size));

	/* (old comment; still true?) FIXME: we need a big lock around realloc()
	 * to avoid concurrent in-place realloc()s messing with the other trailers we access. */
	/* bin_sanity_check(bin_for_addr(ptr)); */ 

	/* remove it from the bins */
	void *our_next_chunk = entry_to_same_range_addr(trailer_for_chunk(ptr)->next, ptr);
	void *our_prev_chunk = entry_to_same_range_addr(trailer_for_chunk(ptr)->prev, ptr);
	
	/* FIXME: make these atomic */
	if (our_prev_chunk) 
	{
		TRAILER_SANITY_CHECK(trailer_for_chunk(our_prev_chunk));
		trailer_for_chunk(our_prev_chunk)->next = addr_to_entry(our_next_chunk);
	}
	else /* !our_prev_chunk */
	{
		/* removing head of the list */
		*INDEX_LOC_FOR_ADDR(ptr) = addr_to_entry(our_next_chunk);
		if (!our_next_chunk)
		{
			/* ... it's a singleton list, so 
			 * - no prev chunk to update
			 * - the index entry should be non-present
			 * - exit */
			assert(INDEX_LOC_FOR_ADDR(ptr)->present == 0);
			/* bin_sanity_check(bin_for_addr(ptr)); */
			return;
		}
	}

	if (our_next_chunk) 
	{
		TRAILER_SANITY_CHECK(trailer_for_chunk(our_next_chunk));
		
		/* may assign NULL here, if we're removing the head of the list */
		trailer_for_chunk(our_next_chunk)->prev = addr_to_entry(our_prev_chunk);
	}
	else /* !our_next_chunk */
	{
		/* removing tail of the list... */
		/* ... and NOT a singleton -- we've handled that case already */
		assert(our_prev_chunk);
	
		/* update the previous chunk's trailer */
		trailer_for_chunk(our_prev_chunk)->next = addr_to_entry(NULL);

		/* nothing else to do here, as we don't keep a tail pointer */
	}
	/* Now that we have deleted the record, our bin should be sane,
	 * modulo concurrent reallocs. */
	/* bin_sanity_check(bin_for_addr(ptr)); */
}

static void pre_nonnull_free(void *ptr, size_t freed_usable_size)
{
	index_delete(ptr, freed_usable_size);
}

static void post_nonnull_free(void *ptr) {}

static void pre_nonnull_nonzero_realloc(void *ptr, size_t size, const void *caller, void *__new)
{
	/* When this happens, we *may or may not be freeing an area*
	 * -- i.e. if the realloc fails, we will not actually free anything.
	 * However, in the case of realloc()ing a *slightly smaller* region, 
	 * the allocator might trash our trailer (by writing its own trailer over it). 
	 * So we *must* delete the entry first,
	 * then recreate it later, as it may not survive the realloc() uncorrupted. */
	index_delete(ptr, malloc_usable_size(ptr));
}
static void post_nonnull_nonzero_realloc(void *ptr, 
	size_t modified_size, 
	size_t old_usable_size,
	const void *caller, void *__new)
{
	if (__new != NULL)
	{
		/* create a new bin entry */
		index_insert(__new, modified_size, caller);
	}
	else 
	{
		/* *recreate* the old bin entry! The old usable size
		 * is the *modified* size, i.e. we modified it before
		 * allocating it, so we pass it as the modified_size to
		 * index_insert. */
		index_insert(ptr, old_usable_size, caller);
	} 
}

/* Mainly for the memtable-perf performance tests...  
 * this function returns a chunk pointer equal to mem,
 * if and only if mem is a valid chunk pointer. Otherwise
 * it returns NULL. FIXME: support interior pointers. */
void *lookup_metadata(void *mem)
{
	struct entry *cur_head = INDEX_LOC_FOR_ADDR(mem);
	size_t object_minimum_size = 0;
	
	do
	{
		void *cur_chunk = entry_ptr_to_addr(cur_head);

		while (cur_chunk)
		{
			if (mem == cur_chunk) return cur_chunk;
			struct trailer *cur_trailer = trailer_for_chunk(cur_chunk);
			cur_chunk = entry_to_same_range_addr(cur_trailer->next, cur_chunk);
		}
		/* we reached the end of the list */
		return NULL; /* HACK: we can do this because the benchmark only passes object
						start addresses. Otherwise we'd have to keep on searching, up to 
						the size of the biggest object allocated so far in the program. */
	} while (object_minimum_size += entry_coverage_in_bytes,
		cur_head-- > &index_region[0]);
	/* We have to assume the object may be a big object whose record is in 
	 * an earlier bin. We should only iterate up to some sane "maximum object size",
	 * which we could track as the biggest object malloc'd so far; 
	 * terminate once object_minimum_size exceeds this. FIXME. */
	
}
