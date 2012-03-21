#include "process.hpp"
#include <fstream>
#include <sstream>
#include <climits>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <malloc.h>
#ifdef MALLOC_USABLE_SIZE_HACK
#include <dlfcn.h>
#include "malloc_usable_size_hack.h"
#else
extern "C" {
extern size_t malloc_usable_size(void *); /* we *must* have this function */
}
#endif
#ifdef HAVE_DLADDR
#include <dlfcn.h>
#endif

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

/* Hard-coded table of allocation sites.
 * NOTE: since we want to support >1 allocation type per function,
 * we also index the table by the object size. BUT there's a complication:
 * dlmalloc (and other mallocs) don't remember the precise object size,
 * just the size after padding for the allocator's alignment (e.g. 1 word).
 * We increment by our trailer size before this padding happens. Then this
 * incremented size is what's padded. 
 *  */

#define PAD_TO_NBYTES(s, n) (((s) % (n) == 0) ? (s) : ((((s) / (n)) + 1) * (n)))
#define USABLE_SIZE_FROM_OBJECT_SIZE(s) (PAD_TO_NBYTES((s) + sizeof (struct trailer) , 4))
#define HEAPSZ_ONE(t) (USABLE_SIZE_FROM_OBJECT_SIZE(sizeof ((t))))

static map<pair<string, size_t>, vector<string> > allocsite_typenames = {
	{ { "_puffs_init", 1102 /* HEAPSZ_ONE(puffs_usermount)*/ }, (vector<string>){ "puffs_usermount" } },
	{ { "_puffs_init", 3382 /* HEAPSZ_ONE(puffs_kargs)*/ }, (vector<string>){ "puffs_kargs" } },
	{ { "makefooblahfunc", 42 }, (vector<string>){ "foo", "blah" } }
};

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
	if (!ret) 
	{
		cerr << "Could not locate metadata for heap object " << (void*)heap_loc << endl;
		return shared_ptr<dwarf::spec::basic_die>();
	}
	void *alloc_site = (void *) ret->alloc_site;
	size_t usable_size = malloc_usable_size(reinterpret_cast<void*>(heap_loc));
	size_t object_size = usable_size - sizeof (struct trailer);
	cerr << "Considering object at " << (void*)heap_loc << endl;
	cerr << "Usable size is " << usable_size << " bytes." << endl;
	cerr << "Object size is " << object_size << " bytes." << endl;
	if (usable_size < 1UL<<29) // sizes >= 512MB are not sane
	{
#if HAVE_DLADDR
		/* 2. Guess what DWARF types were allocated at that allocation site. */
		shared_ptr<type_die> alloc_t;
		#define TOPBIT_MASK (1UL<<(WORD_BITSIZE-1))
		for (unsigned mask = 0; mask != ~0UL; mask = (mask == 0) ? TOPBIT_MASK : ~0UL)
		{
			addr_t addr_to_test = ((addr_t) ret->alloc_site) | mask;
			Dl_info dli;
			/* clear dlerror() */
			dlerror();
			int err = dladdr(reinterpret_cast<void*>(addr_to_test), &dli);
			if (err != 0) /* note unusual error reporting convention */
			{
				auto found = allocsite_typenames.find(
					make_pair(dli.dli_sname, object_size));
				if (found != allocsite_typenames.end())
				{
					auto &vec = found->second;

					// which function allocated the object?
					auto subp = discover_object_descr((addr_t) addr_to_test);
					assert(subp && subp->get_tag() == DW_TAG_subprogram);
					auto t = subp->enclosing_compile_unit()->resolve(vec.begin(), vec.end());
					assert(t);
					alloc_t = dynamic_pointer_cast<type_die>(t);
					if (alloc_t) 
					{

						// FIXME: now install this into the record
						// ret->alloc_site_flag = 1;
						// ret->alloc_site = reinterpret_cast<intptr_t>(&vec->second);
						// FIXME: now use the flag when doing lookup

						// return
						return alloc_t;
					}
				}
				else
				{
					cerr << "Failed to recognise allocsite 0x" << std::hex << addr_to_test << std::dec
						<< " (symbol: " << dli.dli_sname << ", object: " << dli.dli_fname 
							<< ", object size: " << object_size << ")" << endl;
				}
			}
			else
			{
				string symname;
				bool success = this->nearest_preceding_symbol(addr_to_test,
					&symname,
					0,
					0,
					0
				);
				if (success)
				{
					assert(false); // FIXME: refactor the above
				}
				else
				{

					char *reported_error = dlerror();
					cerr << "Failed to find a symbol preceding address 0x" 
						<< std::hex << addr_to_test << std::dec 
						<< " (error: " << string(reported_error ? reported_error : "(no error)") << ")" 
						<< endl;
				}
			}
		}
	#endif

		/* 2. Guess what DWARF types were allocated at that allocation site. */
		cerr << "Heap object discovery not supported for " << (void*)heap_loc << endl;
		cerr << "Caller supplied imprecise static type: " 
			<< (imprecise_static_type ? imprecise_static_type->summary() : "(none)") << endl;
		if (imprecise_static_type)
		{
			cerr << "Imprecise type has ";
			auto opt_sz = imprecise_static_type->calculate_byte_size();
			if (opt_sz) cerr << "size " << *opt_sz << " bytes.";
			else cerr << "indeterminate size.";
			cerr << endl;

			if (opt_sz)
			{
				auto expected_usable_size = USABLE_SIZE_FROM_OBJECT_SIZE(*opt_sz);
				cerr << "One instance of this, with trailer and padding, comes to " 
					<< expected_usable_size << " bytes." << endl;
				if (expected_usable_size == usable_size) 
				{
					cerr << "Sizes match, so going with the caller-supplied type." << endl;
					return imprecise_static_type;
				}
				else
				{
					// FIXME!
					cerr << "WARNING: sizes don't match, but going with caller-supplied anyway."
						<< endl;
					return imprecise_static_type;
				}
			}
		}
	}
	else // usable_size is >= 512MB
	{
		cerr << "Usable size is not sane: " << usable_size << endl;
		return imprecise_static_type;
	}
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
