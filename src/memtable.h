#if defined (X86_64) || (defined (__x86_64__))
#define BIGGEST_MMAP_ALLOWED (1ULL<<46)
#else
#define BIGGEST_MMAP_ALLOWED (1ULL<<(((sizeof (void*))<<3)-2))
#warning "Guessing the maximum mmap() size for this architecture"
// go with 1/4 of the address space if we're not sure (x86-64 is special)
#endif

#include <assert.h>
/* #include <math.h> */
#include <sys/mman.h>
#include <stddef.h>

static inline size_t memtable_mapping_size(
	unsigned entry_size_in_bytes,
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end)
{
	/* NOTE: if addr_begin and addr_end are both zero, we use the full range. */
	/* HACK: we use "long double" because 80-bit precision avoids 
	 * overflow in the whole-address-space case. To do this with
	 * integer arithmetic, we would be trying to construct the number
	 * one bigger than the maximum representable unsigned 64-bit integer. */
	
	// void *test1 = (void*) -1;
	// unsigned long long test2 = (unsigned long long) test1;
	// long double test3 = test2 + 1;
	// assert((long double)(unsigned long long)(void*)-1 != 0);
	
	long double nbytes_covered = (addr_begin == 0 && addr_end == 0) ?
		(((long double)(unsigned long long)(void*)-1) + 1)
		: addr_end - addr_begin;
	long double nbytes_in_table = nbytes_covered / entry_coverage_in_bytes;
	return (size_t) nbytes_in_table;
}
#define MEMTABLE_MAPPING_SIZE_WITH_TYPE(t, range, addr_begin, addr_end) \
	memtable_mapping_size(sizeof(t), (range), (addr_begin), (addr_end))

/* Allocate a memtable. */
static inline void *memtable_new(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end)
{
	size_t mapping_size = memtable_mapping_size(entry_size_in_bytes,
		entry_coverage_in_bytes, addr_begin, addr_end);
	assert(mapping_size <= BIGGEST_MMAP_ALLOWED);
	void *ret = mmap(NULL, mapping_size, PROT_READ|PROT_WRITE, 
		MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
	return ret; /* MAP_FAILED on error */
}
#define MEMTABLE_NEW_WITH_TYPE(t, range, addr_begin, addr_end) \
	memtable_new(sizeof(t), (range), (addr_begin), (addr_end))

/* Get a pointer to the index-th entry. */
static inline void *memtable_index(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end,
	unsigned long index
	)
{
	return (char*) memtable + (entry_size_in_bytes * index);
}
#define MEMTABLE_INDEX_WITH_TYPE(m, t, range, addr_begin, addr_end, index) \
	((t*) memtable_index((m), sizeof(t), (range), (addr_begin), (addr_end), (index)))

/* Get a pointer to the entry for address addr. */
static inline void *memtable_addr(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end,
	void *addr
	)
{
	assert(addr >= addr_begin && addr < addr_end);
	return memtable_index(memtable, entry_size_in_bytes, entry_coverage_in_bytes,
		addr_begin, addr_end, (addr - addr_begin) / entry_coverage_in_bytes);
}
#define MEMTABLE_ADDR_WITH_TYPE(m, t, range, addr_begin, addr_end, addr) \
	((t*) memtable_addr((m), sizeof(t), (range), (addr_begin), (addr_end), (addr)))

/* The inverse of memtable_addr: given a pointer into the table, get the pointer
 * to the base of the region to which the pointed-at entry corresponds. */
static inline void *memtable_entry_range_base(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end, 
	void *memtable_entry_ptr
)
{
	assert(memtable_entry_ptr - memtable < memtable_mapping_size(
		entry_size_in_bytes, entry_coverage_in_bytes, addr_begin, addr_end));

	return (memtable_entry_ptr - memtable) / entry_size_in_bytes
		* entry_coverage_in_bytes
		+ (char*) addr_begin;
}
#define MEMTABLE_ENTRY_RANGE_BASE_WITH_TYPE(m, t, range, addr_begin, addr_end, entry_ptr) \
	memtable_entry_range_base((m), sizeof (t), (range), \
		(addr_begin), (addr_end), (entry_ptr))

/* For an address, get the base address of the region that it belongs to,
 * where a region is the memory covered by exactly one memtable entry. */
static inline void *memtable_addr_range_base(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end, 
	void *addr
)
{
	/* For robustness / testing, express in terms of previous two functions. 
	 * Should compile with -O2 or -O3 to get good code! */
	return memtable_entry_range_base(
			memtable, entry_size_in_bytes, entry_coverage_in_bytes,
			addr_begin, addr_end,
			memtable_addr(
				memtable,
				entry_size_in_bytes, entry_coverage_in_bytes,
				addr_begin, addr_end,
				addr));
}
#define MEMTABLE_ADDR_RANGE_BASE_WITH_TYPE(m, t, range, addr_begin, addr_end, addr) \
	memtable_addr_range_base((m), sizeof (t), (range), (addr_begin), (addr_end), \
		(addr))

/* Like above, but get the offset. */
static inline ptrdiff_t memtable_addr_range_offset(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end, 
	void *addr)
{
	return addr - memtable_addr_range_base(
		memtable, entry_size_in_bytes, entry_coverage_in_bytes,
		addr_begin, addr_end, addr);
}
#define MEMTABLE_ADDR_RANGE_OFFSET_WITH_TYPE(m, t, range, addr_begin, addr_end, addr) \
	memtable_addr_range_offset((m), sizeof (t), (range), (addr_begin), (addr_end), \
		(addr))

/* Delete a memtable. */
static inline int memtable_free(void *memtable, 
 	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_in_bytes,
	void *addr_begin, void *addr_end)
{
	size_t mapping_size = memtable_mapping_size(entry_size_in_bytes, 
		entry_coverage_in_bytes, addr_begin, addr_end);
	return munmap(memtable, mapping_size);
}

/* Some example memtables:
 *
 * the chunktracker:
 * entry is 1 byte,
 * entry covers 1KB memory (around 10 heap chunks?),
 * all addresses are valid;
 * entries are chunk tags (8 bytes)
 * sufficient to locate a chunk within a 1KB region because they're always 8byte-aligned
 * (so top 7 bits suffice)
 * + 1 reserved bit to mean "no chunk" (like NULL) if set to zero (i.e. must be default value)
 * each chunk has a trailer: 
 * next+prev bytes (16 bits), 
 * requested size 
 * (for the dynamic points-to analysis -- record as *difference* from the *effective size*,
 * at most +/-15 bytes? say 5 bits), 
 * alloc site (can be compacted to 32 bits, but use whatever we have left: 43 bits)
 * For a 64-bit address space, this table requires 2^54 entries, each 1 byte
 * whereas we can only mmap 2^46 bytes, i.e. 8 bits short
 * so use a ASSUMED_MAX_HEAP_ADDR of 2^56 (i.e. 64 - 8)
 *
 * the coobjinator:
 * entry is sizeof(std::map<void*, boost::shared_ptr<co_object_group> >), (48 bytes for me)
 * (note: - it's a map because we have to handle multiple objects in the same region;
 *        - it's a pointer-to-group because participant objects are not *all* in one region;
 *        - we use boost::shared_ptr to manage the population of co_object_groups)
 * entry covers 16KB memory (at least),
 * all addresses are valid;
 * entries are maps from addrs (in their range) to the shared co_object_group
 * If we want to use a full 2^46 bytes of map for a 48-bit address space,
 * then 48 bytes per entry gets us 1466015503701 entries,
 * each covering 192 bytes,
 * or scale up by 2^n to cover n more bits,
 * or scale down the map size (so we can fit the chunktracker in our address space too!)
 */
