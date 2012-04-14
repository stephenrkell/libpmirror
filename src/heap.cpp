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
using namespace dwarf::lib; // was: omitted to remove Elf ambiguity
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
	// look for an informed object with equal or lower starting address
	auto upper_bound = informed_heap_descrs.upper_bound(heap_loc);
	auto greatest_le = srk31::greatest_le_from_upper_bound(
		informed_heap_descrs.begin(), informed_heap_descrs.end(), upper_bound,
		// const long unsigned int&, std::pair<const long unsigned int, boost::shared_ptr<dwarf::spec::type_die>
		make_pair(heap_loc, boost::shared_ptr<dwarf::spec::type_die>()), 
		informed_heap_descrs.value_comp());
	if (greatest_le != informed_heap_descrs.end()
		&& greatest_le->second
		&& greatest_le->second->calculate_byte_size()
		&& *greatest_le->second->calculate_byte_size() < heap_loc - upper_bound->first)
	{
		if (out_object_start_addr) *out_object_start_addr = (addr_t) greatest_le->first;
		cerr << "From what the user has informed us, we think that 0x" 
			<< std::hex << heap_loc << std::dec
			<< " is " << (heap_loc - (addr_t) greatest_le->first) << " bytes into an object beginning at 0x"
			<< std::hex << (addr_t) greatest_le->first << std::dec
			<< " described by " << greatest_le->second->summary() << endl;
		return dynamic_pointer_cast<dwarf::spec::basic_die>(greatest_le->second);
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

/* Do I want to pad to 4, 8 or (=== 4 (mod 8)) bytes? 
 * Try 4 mod 8. */
#define PAD_TO_NBYTES(s, n) (((s) % (n) == 0) ? (s) : ((((s) / (n)) + 1) * (n)))
#define PAD_TO_MBYTES_MOD_N(s, n, m) (((s) % (n) <= (m)) \
? ((((s) / (n)) * (n)) + (m)) \
: (((((s) / (n)) + 1) * (n)) + (m)))
// (((s) % (n) <= (m)) ? ((((s) / (n)) * (n)) + (m)) : (((((s) / (n)) + 1) * (n)) + (m)))
#define USABLE_SIZE_FROM_OBJECT_SIZE(s) (PAD_TO_MBYTES_MOD_N( ((s) + sizeof (struct trailer)) , 8, 4))
#define HEAPSZ_ONE(t) (USABLE_SIZE_FROM_OBJECT_SIZE(sizeof ((t))))

static map<pair<string, size_t>, vector<string> > allocsite_typenames = {
	{ { "_puffs_init", /*1102*/ USABLE_SIZE_FROM_OBJECT_SIZE(1100) }, (vector<string>){ "puffs_usermount" } },
	{ { "_puffs_init", /*3382*/ USABLE_SIZE_FROM_OBJECT_SIZE(3380) }, (vector<string>){ "puffs_kargs" } },
	{ { "puffs_framebuf_make", 120 /*USABLE_SIZE_FROM_OBJECT_SIZE(44? 114?)*/ }, (vector<string>){ "puffs_cred" } },
	{ { "kmem_zalloc", USABLE_SIZE_FROM_OBJECT_SIZE(528) }, (vector<string>){ "dirent" } }, 
	{ { "kmem_zalloc", USABLE_SIZE_FROM_OBJECT_SIZE(2320) }, (vector<string>){ "mount" } }, 
	{ { "kmem_alloc", USABLE_SIZE_FROM_OBJECT_SIZE(2836) }, (vector<string>){ "tmpfs_mount" } }, 
	{ { "pool_cache_get_paddr", 196 }, (vector<string>){ "signed char" } }, // HACK
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
	size_t padded_object_size = usable_size - sizeof (struct trailer);
	cerr << "Considering object at " << (void*)heap_loc << endl;
	cerr << "Usable size is " << usable_size << " bytes." << endl;
	cerr << "Padded object size is " << padded_object_size << " bytes." << endl;
	if (usable_size < 1UL<<29) // sizes >= 512MB are not sane
	{
		/* We want the symbol name for the allocation site. 
		 * If we have dladdr and are statically linked, use that. 
		 * Otherwise use nearest_preceding_symbol. */
		optional<string> allocsite_symname;
		optional<addr_t> allocsite_symaddr;
		addr_t allocsite_real_addr = 0UL;
#define TOPBIT_MASK (1UL<<(WORD_BITSIZE-1))
#if HAVE_DLADDR
		if (!is_statically_linked)
		{
		/* 2. Guess what DWARF types were allocated at that allocation site. */
			shared_ptr<type_die> alloc_t;
			for (unsigned mask = 0; mask != ~0UL; mask = (mask == 0) ? TOPBIT_MASK : ~0UL)
			{
				addr_t addr_to_test = ((addr_t) ret->alloc_site) | mask;
				Dl_info dli;
				/* clear dlerror() */
				dlerror();
				int err = dladdr(reinterpret_cast<void*>(addr_to_test), &dli);
				if (err != 0) /* note unusual error reporting convention */
				{
					allocsite_symname = string(dli.dli_sname);
					allocsite_symaddr = optional<Dwarf_Addr>((Dwarf_Addr) dli.dli_saddr);
					allocsite_real_addr = addr_to_test;
					break;
				}
			}
		}
#endif
		
		if (!allocsite_symname)
		{
		/* Try nearest_preceding_symbol. */
			string symname;
			for (unsigned mask = 0; mask != ~0UL; mask = (mask == 0) ? TOPBIT_MASK : ~0UL)
			{
				addr_t addr_to_test = ((addr_t) ret->alloc_site) | mask;
				addr_t symstart;
				bool success = this->nearest_preceding_symbol(addr_to_test,
					&symname,
					&symstart,
					0,
					0
				);
				if (success)
				{
					allocsite_symname = symname;
					allocsite_symaddr = optional<Dwarf_Addr>(symstart);
					allocsite_real_addr = addr_to_test;
					break;
				}
				else
				{
					cerr << "Failed to find a symbol preceding address 0x" 
						<< std::hex << addr_to_test << std::dec << std::endl;
				}
			}
		}
#undef TOPBIT_MASK
		if (allocsite_symname)
		{
			assert(allocsite_symaddr);
			/* We succeeded, by one method or another */
			auto found = allocsite_typenames.find(
				make_pair(*allocsite_symname, usable_size));
			if (found != allocsite_typenames.end())
			{
				auto &vec = found->second;

				// which function allocated the object?
				auto subp = find_subprogram_for_absolute_ip(allocsite_real_addr);
				assert(subp && subp->get_tag() == DW_TAG_subprogram);
				auto t = subp->enclosing_compile_unit()->resolve(vec.begin(), vec.end());
				assert(t);
				auto alloc_t = dynamic_pointer_cast<type_die>(t);
				if (alloc_t) 
				{

					// FIXME: now install this into the record
					// ret->alloc_site_flag = 1;
					// ret->alloc_site = reinterpret_cast<intptr_t>(&vec->second);
					// FIXME: now use the flag when doing lookup

					// return
					cerr << "Recognised allocsite; returning type " << alloc_t->summary() << endl;
					return alloc_t;
				}
			}
			else
			{
				cerr << "Failed to recognise allocsite 0x" 
					<< std::hex << allocsite_real_addr << std::dec
					<< " (symbol: " << *allocsite_symname 
					<< ", offset: 0x" << std::hex << (allocsite_real_addr - *allocsite_symaddr) << std::dec
						<< ", padded object size: " << padded_object_size << ")" << endl;
			}
		}
		else
		{
			cerr << "Failed to find symbol for allocsite bits 0x" 
				<< std::hex << ret->alloc_site << std::dec
				<< endl;
		}



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

void process_image::forget_heap_object_descr(
	addr_t addr
	)
{
	informed_heap_descrs.erase(addr);
}

/* static */ const char *process_image::alloc_list_lib_basename = "libpmirror.so";
/* static */ /* const char *process_image::alloc_list_symname = "__cake_alloc_list_head";  */

} // end namespace pmirror
