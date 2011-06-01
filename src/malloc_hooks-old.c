#define _GNU_SOURCE
#include <stdio.h>
/* Prototypes for __malloc_hook, __free_hook */
#include <malloc.h>
#include <math.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#include "objdiscover.h"

/* Prototypes for our hooks.  */
static void my_init_hook (void);
static void *my_malloc_hook (size_t, const void *);
static void my_free_hook (void*, const void *);
static void *my_memalign_hook (size_t alignment, size_t size, const void *caller);
static void *my_realloc_hook(void *ptr, size_t size, const void *caller);

/* Local variables to hold the next-in-chain hooks. */
static void *(*old_malloc_hook) (size_t, const void *);
static void (*old_free_hook) (void*, const void *);
static void *(*old_memalign_hook) (size_t alignment, size_t size, const void *caller);
static void *(*old_realloc_hook)(void *ptr, size_t size, const void *caller);

        
/* Override initializing hook from the C library. */
void (*__malloc_initialize_hook) (void) = my_init_hook;

/* The trick here is that we keep our own malloc bookkeeping info,
 * to remember the extents of blocks that were actually issued to
 * malloc callers. This is because it's not possible to 
 * discover the extents of an issued block, given a pointer to some
 * arbitrary location in the block, without extra metadata. */

//struct __cake_alloc *__cake_alloc_list_head;

void **bins_region;
void *bins_max_address;
unsigned long recs_allocated;
double average_alloc_size;

/* What's the largest region that mmap will let us map? 
 * Experiments on my x86_64 machine make this 2^46 bytes. YMMV. */
#if defined (X86_64) || (defined (__x86_64__))
#define BIGGEST_MMAP_ALLOWED (1ULL<<46)
#else
#define BIGGEST_MMAP_ALLOWED (1ULL<<(((sizeof (void*))<<3)-2))
#warning "Guessing the maximum mmap() size for this architecture"
// go with 1/4 of the address space if we're not sure (x86-64 is special)
#endif

static void
init_bins_region(void)
{
	/* CLEVER BIT: now we mmap a *large* region of VAS to hold our index.
	 * Each word in this region will point to a list of malloc chunks,.
	 * that is threaded using some extra fields that we stash at the end
	 * of the malloc-allocated chunk.
	 * Let's say for now that each list maps 4KB of heap memory.
	 * For a 32-bit address space, we need one word * (4GB / 4KB) == 4MB of VAS. No problem.
	 * For a 64-bit address space, we need 
	 * one word * (2^64B / 4KB) == 8 * 2^52B == 2^55B of VAS. HMM... no problem?
	 * As it happens, *problem*. What I want is for Linux to keep the mapping in software
	 * but not try to push it to the hardware-walked page tables. Instead I'll have to
	 * write my own segfault handler. */
#define POINTER_SHIFT_BITS 12
	unsigned long mapping_size = (sizeof (void*)) * (1UL<<((sizeof(void*)*8) - POINTER_SHIFT_BITS) /* a.k.a. /4096 */);
	
	/* Linux won't let us map 2^55 bytes of VAS, sadly. Let's make do with
	 * 2 ^ 46. This covers the bottom 1/512th of the address space only.
	 * We could try to allocate 512 of these contiguously, but for now, let's
	 * just make do with one. This will cover the bottom 32 million gigabytes. */
	if (mapping_size > BIGGEST_MMAP_ALLOWED)
	{
	
		fprintf(stderr, "%s: warning: mapping %lld bytes not %ld\n",
			__FILE__, BIGGEST_MMAP_ALLOWED, mapping_size);
		fprintf(stderr, "%s: warning: only bottom 1/%lld of address space is tracked.\n",
			__FILE__, mapping_size / BIGGEST_MMAP_ALLOWED);
		mapping_size = BIGGEST_MMAP_ALLOWED;
		bins_max_address = (void*) ((BIGGEST_MMAP_ALLOWED << POINTER_SHIFT_BITS)-1);
	}
	else bins_max_address = (void*) ~0UL;
	
	void *ret = mmap(NULL, mapping_size, PROT_READ|PROT_WRITE /* PROT_NONE */, 
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE/*|MAP_HUGETLB*/, -1, 0);
	if (ret == MAP_FAILED)
	{
		fprintf(stderr, "error: %s\n", strerror(errno));
	}
	assert(ret != MAP_FAILED);
	bins_region = ret;
	/* Sanity check: can we find the bins region using the link map? 
     * Separate-process tools like ltrace (with our patches) rely on this. */
    assert(&bins_region == dlsym(RTLD_DEFAULT, "bins_region"));
}

static void
my_init_hook (void)
{
    /* save old hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* install our hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
	
	init_bins_region();
}

// void print_head_alloc(void)
// {
// 	fprintf(stderr, "Head alloc is at %p, has begin %p, size %zu bytes, next %p\n",
//             __cake_alloc_list_head, __cake_alloc_list_head->begin,
//             __cake_alloc_list_head->size, __cake_alloc_list_head->next);
// }

#if 0
#define SIZE_MASK = ((sizeof(void*)) - 1)
static size_t aligned_size(size_t size)
{
	if (*p_size & SIZE_MASK == *p_size)
	{
		/* already aligned */
		return old_size;
	}
	else
	{
		/* round up */
		return old_size / (sizeof (void*)) + 1;
	}
}
#undef SIZE_MASK
#endif

struct trailer
{
	void *prev_chunk;
	void *next_chunk;
	const void *alloc_site;
};
static struct trailer *trailer_for_chunk(void *addr)
{
	return (struct trailer*) ((char*) addr + malloc_usable_size(addr)) - 1;
}
static struct trailer *trailer_for_chunk_with_usable_size(void *addr, size_t usable_size)
{
	return (struct trailer*) ((char*) addr + usable_size) - 1;
}

/* sanity check: pointers within trailer should share their top bits */
#define TRAILER_SANITY_CHECK(p_t) \
	assert(((p_t)->next_chunk == 0 || (p_t)->prev_chunk == 0) \
		|| \
		((unsigned long) (p_t)->next_chunk ^ \
		 (unsigned long) (p_t)->prev_chunk) < (1UL<<POINTER_SHIFT_BITS))

static void bin_sanity_check(void **bin_head)
{
	void *cur_chunk = *bin_head;
	while (cur_chunk != NULL)
	{
		TRAILER_SANITY_CHECK(trailer_for_chunk(cur_chunk));
		cur_chunk = trailer_for_chunk(cur_chunk)->next_chunk;
	}
}

static void **bin_for_addr(void *addr)
{
	assert(bins_region);
	/* returns the pointer that anchors the bin */
	return bins_region + (((unsigned long)addr) >> POINTER_SHIFT_BITS);
}

/* forward decl */
//static void
//add_region_rec(void *begin, size_t size, const void *caller);

static void 
add_bin_entry(void *begin, size_t modified_size, const void *caller)
{
	/* add_region_rec(begin, size, caller); */
	/* We *must* have been initialized to continue. So initialize now.
	 * (Sometimes the initialize hook doesn't get called til after we are called.) */
	if (!bins_region) init_bins_region();
	/* The address *must* be in our tracked range. Assert this. */
	assert(begin <= bins_max_address);
	/* Populate our extra fields */
	struct trailer *p_trailer = trailer_for_chunk(begin);
	/* DEBUGGING: sanity check entire bin */
	bin_sanity_check(bin_for_addr(begin));
	void *bin_head_chunk = *bin_for_addr(begin); /* i.e. address of the first chunk in list */
	p_trailer->alloc_site = caller;
	/* Add it to the bins. */
	/* We always point to the start of the chunk. */
	p_trailer->next_chunk = bin_head_chunk;
	p_trailer->prev_chunk = NULL;
	if (p_trailer->next_chunk) trailer_for_chunk(p_trailer->next_chunk)->prev_chunk = begin;
	*bin_for_addr(begin) = begin; // FIXME: make these atomic!
	
	/* sanity check: pointers within trailer should share their top bits */
	TRAILER_SANITY_CHECK(p_trailer);
	if (p_trailer->next_chunk) TRAILER_SANITY_CHECK(trailer_for_chunk(p_trailer->next_chunk));
	if (p_trailer->prev_chunk) TRAILER_SANITY_CHECK(trailer_for_chunk(p_trailer->prev_chunk));
	bin_sanity_check(bin_for_addr(begin));
}

static void
post_successful_alloc(void *begin, size_t modified_size, const void *caller)
{
	add_bin_entry(begin, modified_size, caller);
}
// static void
// add_region_rec(void *begin, size_t size, const void *caller)
// {
// 	struct __cake_alloc *new_cake_alloc = malloc(sizeof(new_cake_alloc));
//     new_cake_alloc->begin = begin;
//     new_cake_alloc->size = size;
//     // FIXME: locking
//     new_cake_alloc->next = __cake_alloc_list_head;
//     __cake_alloc_list_head = new_cake_alloc;
//     recs_allocated++;
//     average_alloc_size = (average_alloc_size * (recs_allocated - 1) + size) / recs_allocated;
//     if (ready) print_guessed_region_type(get_self_image(), begin, size, caller);
// }

static void pre_alloc(size_t *p_size, const void *caller)
{
	/* We increase the size 
	 * by the amount of extra data we store. 
	 * We later use malloc_usable_size to work out where to store our data. */

	/* *p_size = aligned_size(*p_size) + 2 * sizeof (void*); */
	/* *p_size += 2 * sizeof (void*); */
	*p_size += sizeof (struct trailer);
}

static void *
my_malloc_hook (size_t size, const void *caller)
{
    void *result;
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __memalign_hook = old_memalign_hook;
    __realloc_hook = old_realloc_hook;
    /* Call recursively */
    /*printf ("calling malloc (%u)\n", (unsigned int) size);*/
    size_t modified_size = size;
    pre_alloc(&modified_size, caller);
    result = malloc (modified_size);
    if (result) post_successful_alloc(result, modified_size, caller);
    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* printf might call malloc, so protect it too. */
    /* printf ("malloc (%u) returns %p (modified size: %zu)\n", 
      (unsigned int) size, result, modified_size); */
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
    return result;
}

static void delete_bin_entry(void *ptr, size_t freed_usable_size)
{
	/* The freed_usable_size is not strictly necessary. It was added
	 * for handling realloc after-the-fact. In this case, by the time we
	 * get called, the usable size has already changed. However, after-the-fact
	 * is a broken way to handle realloc(), because in the case of a *smaller*
	 * realloc'd size, where the realloc happens in-place, realloc() will overwrite
	 * our trailer with its own (regular heap metadata) trailer, breaking the list.
	 */
	TRAILER_SANITY_CHECK(trailer_for_chunk_with_usable_size(ptr, freed_usable_size));
	/* sanity check will fail until we fix up the usable size mismatch 
	 * -- FIXME: we need a big lock around realloc() to avoid concurrent 
	 * in-place realloc()s messing with the other trailers we access. */
	/* bin_sanity_check(bin_for_addr(ptr)); */ 

	/* remove it from the bins */
	void *our_next_chunk = trailer_for_chunk_with_usable_size(ptr, freed_usable_size)->next_chunk;
	void *our_prev_chunk = trailer_for_chunk_with_usable_size(ptr, freed_usable_size)->prev_chunk;
	
	/* FIXME: make these atomic */
	if (our_prev_chunk) 
	{
		TRAILER_SANITY_CHECK(trailer_for_chunk(our_prev_chunk));
		trailer_for_chunk(our_prev_chunk)->next_chunk = our_next_chunk;
	}
	else /* !our_prev_chunk */
	{
		/* removing head of the list */
		*bin_for_addr(ptr) = our_next_chunk;
		if (!our_next_chunk)
		{
			/* ... it's a singleton list, so 
			 * - no prev chunk to update
			 * - the bin ptr should be null
			 * - exit */
			assert(*bin_for_addr(ptr) == NULL);
			bin_sanity_check(bin_for_addr(ptr));
			return;
		}
	}

	if (our_next_chunk) 
	{
		TRAILER_SANITY_CHECK(trailer_for_chunk(our_next_chunk));
		
		/* may assign NULL here, if we're removing the head of the list */
		trailer_for_chunk(our_next_chunk)->prev_chunk = our_prev_chunk;
	}
	else /* !our_next_chunk */
	{
		/* removing tail of the list... */
		/* ... and NOT a singleton -- we've handled that case already */
		assert(our_prev_chunk);
	
		/* update the previous chunk's trailer */
		trailer_for_chunk(our_prev_chunk)->next_chunk = NULL;

		/* nothing else to do here, as we don't keep a tail pointer */
	}
	/* Now that we have deleted the record, our bin should be sane,
	 * modulo concurrent reallocs. */
	bin_sanity_check(bin_for_addr(ptr));
}

static void pre_nonnull_free(void *ptr, size_t freed_usable_size)
{
	delete_bin_entry(ptr, freed_usable_size);
}

/* forward decl */
//static void delete_region_rec_for(void *ptr);

static void post_nonnull_free(void *ptr)
{
	/* delete_region_rec_for(ptr); */
}
// static void delete_region_rec_for(void *ptr)
// {
// /*    if (__cake_alloc_list_head->begin == ptr)
//     {
//     	void *old = __cake_alloc_list_head;
//         __cake_alloc_list_head = __cake_alloc_list_head->next;
//         free_func(old);   
//     }    
//     else
//     {*/
// 	    int found = 0;
// 	    size_t saved_size;
//         struct __cake_alloc *prev_node = NULL;
//         for (struct __cake_alloc *n = __cake_alloc_list_head;
//             	    n != NULL;
//                     prev_node = n, n = n->next)
//         {
//             if (n->begin == ptr)
//             {
//         	    found = 1;
//                 if (prev_node != NULL) prev_node->next = n->next;
//                 else __cake_alloc_list_head = n->next;
//                 saved_size = n->size;
//                 free(n);
//                 break;   
//             }
//         }
// 	    assert(found);
// 	    average_alloc_size = (average_alloc_size * recs_allocated - saved_size) / (recs_allocated - 1);
//         recs_allocated--;
// /*    }*/
// }

static void
my_free_hook (void *ptr, const void *caller)
{
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __memalign_hook = old_memalign_hook;
    __realloc_hook = old_realloc_hook;
    /* Call recursively */
    /*if (ptr != NULL) printf ("freeing pointer %p\n", ptr);*/
	if (ptr != NULL) pre_nonnull_free(ptr, malloc_usable_size(ptr));
    free (ptr);
    if (ptr != NULL) post_nonnull_free(ptr);
    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* printf might call free, so protect it too. */
    /*printf ("freed pointer %p\n", ptr);*/
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
}

static void *
my_memalign_hook (size_t alignment, size_t size, const void *caller)
{
    void *result;
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __memalign_hook = old_memalign_hook;
    __realloc_hook = old_realloc_hook;
    /* Call recursively */
	size_t modified_size = size;
	pre_alloc(&modified_size, caller);
    result = memalign(alignment, modified_size);
    if (result) post_successful_alloc(result, modified_size, caller);
    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* printf might call free, so protect it too. */
    /*printf ("memalign (%u, %u) returns %p\n", (unsigned) alignment, (unsigned) size, result);*/
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
    return result;
}

static void pre_nonnull_nonzero_realloc(void *ptr, size_t size, const void *caller, void *__new)
{
	/* When this happens, we *may or may not be freeing an area*
	 * -- i.e. if the realloc fails, we will not actually free anything.
	 * However, in the case of realloc()ing a *slightly smaller* region, 
	 * the allocator might trash our trailer (by writing its own trailer over it). 
	 * So we *must* delete the entry first,
	 * then recreate it later, as it may not survive the realloc() uncorrupted. */
	delete_bin_entry(ptr, malloc_usable_size(ptr));
}
static void post_nonnull_nonzero_realloc(void *ptr, 
	size_t modified_size, 
	size_t old_usable_size,
	const void *caller, void *__new)
{
	/* delete_region_rec_for(ptr); */
	/* if (__new != NULL) add_region_rec(__new, size, caller); */
	if (__new != NULL)
	{
		/* create a new bin entry */
		add_bin_entry(__new, modified_size, caller);
	}
	else 
	{
		/* *recreate* the old bin entry! The old usable size
		 * is the *modified* size, i.e. we modified it before
		 * allocating it, so we pass it as the modified_size to
		 * add_bin_entry. */
		add_bin_entry(ptr, old_usable_size, caller);
	} 
}

static void *
my_realloc_hook(void *ptr, size_t size, const void *caller)
{
    void *result;
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __memalign_hook = old_memalign_hook;
    __realloc_hook = old_realloc_hook;
	size_t old_usable_size;
    /* Call recursively. First we eliminate the cases where
     * realloc() degenerates into either malloc or free. */
    if (ptr == NULL)
    {
    	/* We behave like malloc(). 
		 * Call nothing here, because we don't currently pre-instrument malloc. */
    }
	else if (size == 0)
	{
		/* We behave like free(). */
		pre_nonnull_free(ptr, malloc_usable_size(ptr));
	}
	else
	{
		/* We are doing a bone fide realloc. This might fail, leaving the
		 * original block untouched. 
		 * If it changes, we'll need to know the old usable size to access
		 * the old trailer. */
		old_usable_size = malloc_usable_size(ptr);
		pre_nonnull_nonzero_realloc(ptr, size, caller, result);
	}
	
	/* Modify the size, as usual, *only if* size != 0 */
    size_t modified_size = size;
	if (size != 0)
	{
    	pre_alloc(&modified_size, caller);
	}

    result = realloc(ptr, modified_size);
	
	if (ptr == NULL)
	{
		/* like malloc() */
		if (result) post_successful_alloc(result, modified_size, caller);
	}
	else if (size == 0)
	{
		/* like free */
		post_nonnull_free(ptr);
	}
	else
	{
		/* bona fide realloc */
		post_nonnull_nonzero_realloc(ptr, modified_size, old_usable_size, caller, result);
	}

    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_memalign_hook = __memalign_hook;
    old_realloc_hook = __realloc_hook;
    /* printf might call free, so protect it too. */
    /* printf ("realigned pointer %p to %p (requested size %u, modified size %u)\n", ptr, result,  
      (unsigned) size, (unsigned) modified_size); */
    /* Restore our own hooks */
    __malloc_hook = my_malloc_hook;
    __free_hook = my_free_hook;
    __memalign_hook = my_memalign_hook;
    __realloc_hook = my_realloc_hook;
    return result;
}

/*int
main (void)
{
	return 0;
}*/
#undef POINTER_SHIFT_BITS	
