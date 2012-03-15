#include "process.hpp"
#include <fstream>
#include <sstream>
#include <climits>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <malloc.h>

extern "C" {
#include "heap_index.h"
}
namespace pmirror {

using namespace dwarf;
/*using namespace dwarf::lib;*/ // omitted to remove Elf ambiguity
using std::string;
using std::cerr;
using std::endl;
using std::pair;
using std::make_pair;

using boost::dynamic_pointer_cast;
using boost::shared_ptr;

using dwarf::spec::basic_die;
using dwarf::spec::subprogram_die;
using dwarf::spec::type_die;
using dwarf::spec::variable_die;
using dwarf::spec::with_static_location_die;
using dwarf::spec::compile_unit_die;

boost::shared_ptr<dwarf::spec::basic_die> 
process_image::discover_heap_object(addr_t heap_loc,
	boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type,
	addr_t *out_object_start_addr)
{
	auto found = informed_heap_descrs.find(heap_loc);
	if (found == informed_heap_descrs.end())
	{
		// look for the next address strictly smaller
		auto upper_bound = informed_heap_descrs.upper_bound(heap_loc);
		if (upper_bound != informed_heap_descrs.end()
			&& upper_bound->second->calculate_byte_size()
			&& *upper_bound->second->calculate_byte_size() < heap_loc - upper_bound->first)
		{
			found = upper_bound;
		}
	}
	
	if (found != informed_heap_descrs.end())
	{
		if (out_object_start_addr) *out_object_start_addr = (addr_t) found->first;
		return dynamic_pointer_cast<dwarf::spec::basic_die>(found->second);
	}
	else if (is_local)
	{
		/* use the local version */
		return discover_heap_object_local(heap_loc, 
			imprecise_static_type, out_object_start_addr);
	}
	else
	{
		/* use the remote version */
		return discover_heap_object_remote(heap_loc, 
			imprecise_static_type, out_object_start_addr);
	}
}

/* Hard-coded table of allocation sites. */

boost::shared_ptr<dwarf::spec::basic_die> 
process_image::discover_heap_object_local(addr_t heap_loc,
	boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type,
	addr_t *out_object_start_addr)
{
	/* 1. Get the allocation site from the memtable. */
	assert(index_region);
	struct trailer *ret = lookup_object_info(
		(const void *)heap_loc, 
		(void **) out_object_start_addr
	);
	if (!ret) return shared_ptr<dwarf::spec::basic_die>();
	void *alloc_site = (void *) ret->alloc_site;
	
	/* 2. Guess what DWARF types were allocated at that allocation site. */
	cerr << "Heap object discovery failed for " << (void*)heap_loc << endl;
	assert(false);
	
}

boost::shared_ptr<dwarf::spec::basic_die> 
process_image::discover_heap_object_remote(addr_t heap_loc,
	boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type,
	addr_t *out_object_start_addr)
{
	assert(false);
	/* How to do remote access to a memtable:
	 *
	 * - in memtable.h, typedef-ify the pointers that we use 
	 *   to access the table and trailers
	 * - make memtable.h multiple-inclusion-safe (i.e. includes nothing itself, #undefs stuff)
	 * - include memtable.h a second time but with different #defines
	 *   and in a different C++ namespace...
	 * - ... so that we use unw_read_ptr
	 * - make sure none of the poiner usages in it are susceptible to the "->" bug
	 * - then we should have a working set of remote::memtable_* functions!
	 */
}
void process_image::inform_heap_object_descr(
	addr_t addr,
	boost::shared_ptr<dwarf::spec::type_die> descr)
{
	/* Here we let the user tell us the DWARF type of a heap object,
	 * such that later calls will discover this information. */
	informed_heap_descrs.insert(std::make_pair(addr, descr));
}

/* static */ const char *process_image::alloc_list_lib_basename = "libpmirror.so";
/* static */ /* const char *process_image::alloc_list_symname = "__cake_alloc_list_head";  */

} // end namespace pmirror
