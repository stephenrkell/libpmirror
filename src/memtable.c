/* Allocate a memtable. */
void *memtable_new(
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_range_in_bytes,
	void *addr_begin, void *addr_end)
{

}
#define MEMTABLE_NEW_WITH_TYPE(t, range, bitmask) \
	memtable_new(sizeof(t), (range), (bitmask))

void *memtable_index(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_range_in_bytes,
	void *addr_begin, void *addr_end,
	unsigned long index
	)
{
	return (char*) memtable + (entry_size_in_bytes * index);
}
#define MEMTABLE_INDEX_WITH_TYPE(m, t, range, bitmask, index) \
	((t*) memtable_index((m), sizeof(t), (range), (bitmask), (index)))

void *memtable_addr(
	void *memtable,
	unsigned entry_size_in_bytes, 
	unsigned entry_coverage_range_in_bytes,
	void *addr_begin, void *addr_end,
	void *addr
	)
{
	assert(addr >= addr_begin && addr < addr_end);
	return memtable_index(memtable, entry_size_in_bytes, entry_coverage_range_in_bytes,
		addr_begin, addr_end, (addr - addr_begin) / entry_size_in_bytes);
}
#define MEMTABLE_ADDR_WITH_TYPE(m, t, range, bitmask, addr) \
	((t*) memtable_addr((m), sizeof(t), (range), (bitmask), (addr)))

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

/* Delete a memtable. */
void *memtable_free(void *memtable);
