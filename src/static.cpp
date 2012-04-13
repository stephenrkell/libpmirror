#include "process.hpp"
#include <fstream>
#include <sstream>
#include <climits>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cstring> /* for basename(), among other things -- must be the GNU version */
#include <fileno.hpp>
#include <link.h>
#include <gelf.h>

#include <srk31/ordinal.hpp>
#include <srk31/algorithm.hpp>

namespace pmirror {

using namespace dwarf;
using lib::Dwarf_Off;
using lib::Dwarf_Addr;
/*using namespace dwarf::lib;*/ // omitted to remove Elf ambiguity
using std::string;
using std::cerr;
using std::endl;
using std::pair;
using std::make_pair;

using boost::dynamic_pointer_cast;
using boost::shared_ptr;

using dwarf::spec::abstract_dieset;
using dwarf::spec::basic_die;
using dwarf::spec::subprogram_die;
using dwarf::spec::type_die;
using dwarf::spec::variable_die;
using dwarf::spec::with_static_location_die;
using dwarf::spec::compile_unit_die;

/* Rethinking static object location. 
 * Given an address, we want the ability to discover 
 * - DWARF information for the object(s) overlapping that address
 * - linker symbols for the object(s) overlapping that address.
 * Queries might ask for the innermost object
 * (almost equivalent to "smallest"),
 * outermost, 
 * next-under, etc.
 *
 * The linker case is complicated by the fact that symbols actually
 * denote just an address, but often (not always) logically denote regions
 * based at that address. So to turn them into objects requires
 * some sort of heuristic for the "length" of each symbol. For the
 * moment, we ignore this problem and just assume that symbols
 * define a flat partitioning of the address space.
 *
 * The debug case is complicated by the fact that don't want to keep
 * open the DIE handles on all the DIEs denoting static objects. 
 * We can just store position_and_path objects I guess.
 * 
 * Let's suppose we have an interval tree which allows repeated nesting
 * i.e. we can have interval (a, b) underneath (a, b).
 * Each node in the tree is labelled with 
 * a symbol reference (probably GElf_Sym or an Elf_Data, symnum pair)
 * or
 * a DIE position_and_path, 
 * meaning that the referenced DIE includes the treenode's range
 * (i.e. precisely ).
 * This might be somewhat space-inefficient in the case of CU DIEs that have
 * thousands of entries in their rangelists.
 * However, it should be time-efficient for lookups, since we have effectively
 * pre-fragmented the space into divisions that are meaningful,
 * so are likely to cleanly include the intervals of deeper DIEs (subprograms, variables).
 *
 * First pass: we implement the interval tree for ELF symbols only, so that
 * we can reimplement dladdr() (which is not available on some systems, nor for
 * statically linked binaries).
 */

process_image::objects_iterator 
process_image::find_object_for_addr(unw_word_t addr)
{
    for (auto i_entry = this->objects.begin(); i_entry != this->objects.end(); ++i_entry)
	{
    	/* Test whether this addr is within this library's mapped regions. */
        if (addr >= i_entry->first.first
            && addr < i_entry->first.second)
        {
        	return i_entry;
        }
    }
	return objects.end();
}

bool
process_image::nearest_preceding_symbol(addr_t addr,
	string *out_sym_name,
	addr_t *out_sym_start,
	size_t *out_sym_size,
	string *out_object_fname
)
{
	// HACK: disable the intervals-based impl for now
// 	auto found = intervals.find(/*interval<addr_t>::right_open(addr, addr)*/ addr);
// 	/* FIXME: if we succeeded, we also want to return the object filename
// 	 * and its base address, like dladdr() does. */
// 	/* FIXME: want to get not just any old interval, but *all* intervals
// 	 * overlapping our addr, then find the ELF interval.s */
// 	if (found != intervals.end())
// 	{
// 		assert(found->second.kind == interval_descriptor::ELF_DESCRIPTOR);
// 		auto symname = found->second.elf_sym.get_symname();
// 		if (out_sym_name && symname) *out_sym_name = *symname;
// 		assert(!out_sym_start);
// 		assert(!out_sym_size);
// 		assert(!out_object_fname);
// 		return true;
// 	}
// 	return false ;//optional<optional<string> >();

	cerr << "Addr is 0x" << std::hex << addr << std::dec << endl;

	/* This gives us either a direct hit on addr, or the next symbol *past* addr. */
	auto result = srk31::greatest_le_from_upper_bound(
		addr_to_sym_map.begin(),
		addr_to_sym_map.end(),
		addr_to_sym_map.upper_bound(addr),
		make_pair(addr, (const char *) 0),
		addr_to_sym_map.value_comp()
	);
	if (result != addr_to_sym_map.end())
	{
		*out_sym_name = result->second ? string(result->second) : string();
		if (out_sym_start) *out_sym_start = result->first;
		assert(!out_sym_size);
		assert(!out_object_fname);
		return true;
	} else return false;
}

process_image::files_iterator 
process_image::find_file_for_addr(unw_word_t addr)
{
	process_image::files_iterator i_file;
    assert(files.size() > 0);
    
// 	/* HACK: if address is in the PLT or some other runtime artifact,
//      * patch that up here. */
//     if (this->is_linker_code((void*)ip))
//     {
// 		/* use libunwind to get the name of the procedure */
//         char fn_name[4096];
//         int unw_ret;
//         unw_ret = _UPT_get_proc_name(unw_as, ip, fn_name, sizeof fn_name, NULL, unw_priv);
// 		assert(unw_ret == 0);
//         std::cerr << "libunwind thinks ip 0x" << std::hex << ip << std::dec
//         	<< " is under symbol: " << fn_name << std::endl;
// 	}

    auto i_entry = find_object_for_addr(addr);
    if (i_entry == objects.end()) return files.end();

    auto found = this->files.find(i_entry->second.seg_descr);
    if (found != this->files.end())
    {
        std::cerr << "Found that address 0x" << std::hex << addr
            << " is in image of file \"" << found->first << "\"" << std::endl;
        return found;
    }
    else
    {
        /* FIXME: this occurs when there is an entry in objects
         * but no corresponding entry in files. Find out why this
         * might happen. Seems to be for seg_descr
         * like "/usr/lib/gconv/gconv-modules.cache\000..."*/
        std::cerr << "Warning: object at " << (void*) i_entry->first.first
         << " (description: '" << i_entry->second.seg_descr << "') "
         << " has no entry in files map" << std::endl;
		// HMM: on NetBSD it happens for BSS segments of the executable
		return i_executable;
        //return files.end();
    }
}

abstract_dieset::iterator
process_image::cu_iterator_for_dieset_relative_addr(
	files_iterator i_file,
	addr_t dieset_relative_addr)
{
	/* Since we're _addr not _ip, try the variable cache first. */
	auto& lookup = i_file->second.p_root->addr_lookup;
	auto upper_bound = lookup.upper_bound(dieset_relative_addr);
	auto found = srk31::greatest_le_from_upper_bound(lookup.begin(), lookup.end(), upper_bound,
		make_pair(dieset_relative_addr, make_pair(0ULL, 0UL)), lookup.value_comp());
	if (found != lookup.end())
	{
		cerr << "Found static var, start 0x" << std::hex << found->first << std::dec
			<< ", length " << found->second.second << ", in compile unit at 0x" 
			<< std::hex << found->second.first << std::dec << endl;
		
		/* Okay -- make the iterator. */
		abstract_dieset::path_type path;
		path.push_back(0UL);
		path.push_back(found->second.first);
		abstract_dieset::position_and_path(
			(abstract_dieset::position){ i_file->second.p_ds.get(), path.back() },
			path);
	}
	else if (found == lookup.end())
	{
		cerr << "Did not find static var. Will try subroutines." << endl;
	}

	/* Use aranges */
	auto& aranges = i_file->second.p_df->get_aranges();
	cerr << "aranges has " << aranges.count() << " entries (really: " 
		<< aranges.cnt
		<< " (base at " << aranges.arange_block_base()
		<< ")." << endl;
	lib::Dwarf_Addr start;
	lib::Dwarf_Unsigned len;
	lib::Dwarf_Off cu_off;
	int ret = aranges.get_info_for_addr(
		dieset_relative_addr, &start, &len, &cu_off
	);
	if (ret == DW_DLV_OK)
	{
		cerr << "Found arange, start 0x" << std::hex << start << std::dec
			<< ", length " << len << ", in compile unit at 0x" 
			<< std::hex << cu_off << std::dec << endl;
			
		abstract_dieset::path_type path;
		path.push_back(0UL);
		path.push_back(cu_off);
		return abstract_dieset::position_and_path(
			(abstract_dieset::position){ i_file->second.p_ds.get(), path.back() },
			path);
	}
	else
	{
		cerr << "Did not find arange (" << /*dwarf_errmsg(*aranges.p_last_error) <<*/ ")." << endl;
		return i_file->second.p_ds->end();
	}
}


abstract_dieset::iterator
process_image::find_more_specific_die_for_dieset_relative_addr(
	abstract_dieset::iterator under_here,
	unw_word_t dieset_relative_addr)
{
	// This is too expensive to do from toplevel! 
	assert(under_here.base().off != 0UL);
	
	assert(under_here.base().p_d->get_offset() == under_here.base().off);
	unsigned initial_depth = under_here.base().path_from_root.size();
	auto initial_under_here = under_here;
	
	abstract_dieset& ds = *under_here.base().p_ds;

	/* Try the cache... */
	location_refinements_cache_t::iterator found;
	if (
		(found = 
			location_refinements_cache.find(
				make_pair(
					under_here.base(),
					dieset_relative_addr
				)
			)
		) != location_refinements_cache.end())
	{
		if (found->second == ds.end().base()) 
		{
			// hit, but a negative result (no deeper DIE)
			return ds.end().base();
		}
		else
		{
			// hit, and a positive result
			assert(found->second.off != under_here.base().off);
			abstract_dieset::iterator to_return = found->second;
			assert(to_return.base().p_d->get_offset() == to_return.base().off);
			return to_return;
		}
	}
	// else run the slow path

	std::cerr << "*** search for more specific match for dieset relative addr 0x" 
		<< std::hex << dieset_relative_addr << std::hex
		<< " than "
		<< (*initial_under_here)->summary()
		<< std::endl;
	
	
	//dwarf::spec::abstract_dieset::bfs_policy bfs_state;
	
	/* We use two optimisations in this function, to avoid searching huge
	 * numbers of DIEs at each call.
	 * 
	 * 1. Cache returned mappings: (under_here, addr) --> there
	 * 
	 * 2. Instead of straight BFS, we want a modification: don't bother
	 * descending into subtrees that will not contain any  */
	 
	struct location_subtree_policy :  public abstract_dieset::bfs_policy
	{
		typedef abstract_dieset::bfs_policy super;
		int increment(abstract_dieset::iterator_base& base)
		{
			/* If our current DIE is 
			 * a with_static_location_die
			 * OR
			 * is in the "interesting set"
			 * of DIEs that have no location but might contain such DIEs,
			 * we increment *with* enqueueing children.
			 * Otherwise we increment without enqueueing children.
			 */
			if (dynamic_pointer_cast<dwarf::spec::with_static_location_die>(base.p_d))
			{
				return super::increment(base);
			}
			else
			{
				switch (base.p_d->get_tag())
				{
					case DW_TAG_namespace:
					case DW_TAG_module:
					case DW_TAG_imported_unit:
					case DW_TAG_imported_module:
					case DW_TAG_partial_unit:
					case DW_TAG_common_block:
					case DW_TAG_common_inclusion:
						return super::increment(base);
						break;
					default:
						return super::increment_skipping_subtree(base);
						break;
				}
			}
		}
	} search_state;
	
	abstract_dieset::iterator depthfirst_i(under_here);
	depthfirst_i++; // now we have the first child, or something higher
	abstract_dieset::iterator i_d(depthfirst_i, search_state);
	for (; i_d != ds.end() && i_d.base().path_from_root.size() > initial_depth; ++i_d)
	{
		unsigned depth = i_d.base().path_from_root.size();
		
// 		std::cerr << "*** considering " 
// 			<< (*i)->get_spec().tag_lookup((*i)->get_tag())
// 			<< " at 0x"
// 			<< std::hex << (*i)->get_offset() << std::dec << std::endl;
// 			//<< std::hex << i << std::endl;
		auto p_has_location = dynamic_pointer_cast<spec::with_static_location_die>(*i_d);
		if (p_has_location && p_has_location->contains_addr(dieset_relative_addr))
		{
			std::cerr << "*** found more specific match, "
				<< (*i_d)->summary()
				<< ", for dieset-relative addr 0x" 
				<< std::hex << dieset_relative_addr << std::hex
				<< " (than " << (*initial_under_here)->summary() << ")"
				/*<< ": " << *p_has_location*/ << std::endl;
				
			// add to cache
			location_refinements_cache.insert(
				make_pair(
					make_pair(
						under_here.base(),
						dieset_relative_addr
					),
					i_d.base()
				)
			);
			
			// return
			return i_d.base();
		}
		//else std::cerr << (p_has_location ? "no static location" : "does not contain addr") << std::endl;
	}
	std::cerr << "*** no more specific match for dieset-relative addr 0x" 
		<< std::hex << dieset_relative_addr << std::hex
		<< " (than " << (*initial_under_here)->summary() << ")"
		<< std::endl;
	
	// add negative result to cache
	location_refinements_cache.insert(
		make_pair(
			make_pair(
				under_here.base(),
				dieset_relative_addr
			),
			ds.end().base()
		)
	);
	
	return ds.end().base();
}

/* Now we have the user-facing interface for locating static objects' DIEs. */
shared_ptr<subprogram_die> 
process_image::find_subprogram_for_absolute_ip(unw_word_t ip)
{
	auto iter = cu_iterator_for_absolute_ip(ip);
	auto found = find_containing_die_for_absolute_addr(
			ip,
			[](const basic_die& d) { return d.get_tag() == DW_TAG_subprogram; }, // pred
			false, // innermost? no, outermost should be fine (BUT nested subprograms?)
			iter
		);
	auto found_subprogram = dynamic_pointer_cast<subprogram_die>(found);
	assert(found_subprogram);
	return found_subprogram;
}
shared_ptr<compile_unit_die> 
process_image::find_compile_unit_for_absolute_ip(unw_word_t ip)
{
	auto iter = cu_iterator_for_absolute_ip(ip);
	assert(*iter);
	auto found_compile_unit = dynamic_pointer_cast<compile_unit_die>(*iter);
	return found_compile_unit;
}
abstract_dieset::iterator
process_image::cu_iterator_for_absolute_ip(unw_word_t ip)
{
	process_image::files_iterator found_file = find_file_for_addr(ip);
	assert(found_file != this->files.end());
	abstract_dieset& ds = *found_file->second.p_ds;
	auto base_addr = get_dieset_base(ds);
	assert(ip >= base_addr);
	
	auto p_toplevel = dynamic_pointer_cast<lib::file_toplevel_die>(ds.toplevel());
	
	auto found = p_toplevel->cu_intervals.find(ip - base_addr);
	assert(found != p_toplevel->cu_intervals.end());
	Dwarf_Off found_off = found->second;
	abstract_dieset::path_type path(1, 0UL);
	path.push_back(found->second);
	return abstract_dieset::position_and_path(
		(abstract_dieset::position){ found_file->second.p_ds.get(), found->second }, 
		path
	);
	
// 	auto found = find_containing_die_for_absolute_addr(
// 		ip,
// 		[](const basic_die& d) { return d.get_tag() == DW_TAG_compile_unit; }, // pred
// 		false // innermost? no, outermost should be fine
// 	);
// 	return found->iterator_here();
}
shared_ptr<with_static_location_die> 
process_image::find_containing_die_for_absolute_addr(unw_word_t addr, bool innermost)
{
	auto found = find_containing_die_for_absolute_addr(
			addr,
			[](const basic_die& d) { return true; }, // pred
			innermost // innermost?
		);
	if (!found) 
	{
		cerr << "Static DIE lookup failed for 0x"
			<< std::hex << addr << std::dec
			<< ". Object has no debug info, or perhaps is a linker artifact?" << endl;
		return shared_ptr<with_static_location_die>();
	}
	auto found_with_static_location = dynamic_pointer_cast<with_static_location_die>(found);
	assert(found); // cast should not fail
	return found;
}
// implementation of the above
template <typename Pred>
shared_ptr<with_static_location_die> 
process_image::find_containing_die_for_absolute_addr(
	unw_word_t addr,
	const Pred& pred,
	bool innermost,
	optional<abstract_dieset::iterator> start_here /* = optional<abstract_dieset::iterator>() */)
{
	process_image::files_iterator found_file = find_file_for_addr(addr);
	if (found_file == this->files.end())
	{
		cerr << "Warning: no file found for addr 0x" << std::hex << addr << std::dec << endl;
		return shared_ptr<with_static_location_die>();
	}
	abstract_dieset& ds = *found_file->second.p_ds;
	unw_word_t dieset_relative_addr = addr - get_dieset_base(ds);

	if (!start_here || start_here->base().off == 0UL)
	{
		start_here = cu_iterator_for_dieset_relative_addr(
			found_file, 
			dieset_relative_addr);
	}

	auto found = find_containing_die_for_dieset_relative_addr(
			ds,
			dieset_relative_addr,
			pred, // pred
			innermost, // innermost?
			start_here
		);
	auto retval = dynamic_pointer_cast<spec::with_static_location_die>(found);
	assert(retval || !found); // cast should not fail
	return retval;
}

/* This is the main implementation. 
 * It uses find_more_specific_die_for_dieset_relative_addr. */
template <typename Pred>
shared_ptr<with_static_location_die> 
process_image::find_containing_die_for_dieset_relative_addr(
	abstract_dieset& ds,
	Dwarf_Off dieset_relative_addr, 
	const Pred& pred,
	bool innermost,
	optional<abstract_dieset::iterator> start_here /* = optional<abstract_dieset::iterator>() */)
{
	auto under_here = start_here ? *start_here : ds.begin();
	abstract_dieset::iterator found_deeper = under_here;
	abstract_dieset::iterator last_to_satisfy = ds.end();
	while (found_deeper != ds.end())
	{
		cerr << "Trying predicate at offset 0x" << std::hex << found_deeper.base().off << std::dec
			<< " a.k.a. " << (*found_deeper)->summary() << endl;
		if (pred(**found_deeper))
		{
			cerr << "Predicate includes " << (*found_deeper)->summary() << endl;
			last_to_satisfy = found_deeper;
			if (!innermost) break;
			// else continue searching
		}
		else
		{
			cerr << "Predicate rules out " << (*found_deeper)->summary() << endl;
		}
		
		// try to go lower
		found_deeper = find_more_specific_die_for_dieset_relative_addr(
			found_deeper,
			dieset_relative_addr);
	}
	if (last_to_satisfy == ds.end())
	{
		cerr << "Warning: no satisfying DIEs covered dieset-relative addr 0x" 
			<< std::hex << dieset_relative_addr << std::dec << endl;
		return shared_ptr<with_static_location_die>();
	}
	else
	{
		auto found = *last_to_satisfy;
		assert(found);
		auto retval = dynamic_pointer_cast<with_static_location_die>(found);
		if (!retval)
		{
			cerr << "Found unexpected DIE for static object: " << found->summary() << endl;
			assert(false);
		}
		return retval;
	}
}
/* Discover a DWARF variable or subprogram for an arbitrary object in
 * the program. These will usually be static-alloc'd objects, but in
 * DwarfPython they could be heap-alloc'd objects that have been
 * specialised in their layout. Could they be stack-alloc'd? I guess so,
 * although you'd better hope that the C code which allocated them won't
 * be accessing them any more. */
boost::shared_ptr<spec::with_static_location_die> 
process_image::discover_object(addr_t addr, addr_t *out_object_start_addr)
{
	boost::shared_ptr<dwarf::spec::basic_die> most_specific
	 = dynamic_pointer_cast<dwarf::spec::basic_die>(
	 	this->find_most_specific_die_for_absolute_addr(addr));

	// if not failed already...
	if (most_specific)
	{
		// we want either a variable or a subprogram
		while (!(
				most_specific->get_tag() == DW_TAG_subprogram
				|| (most_specific->get_tag() == DW_TAG_variable &&
					dynamic_pointer_cast<dwarf::spec::variable_die>(most_specific)
						->has_static_storage())))
		{
			most_specific = most_specific->get_parent();
			if (most_specific->get_tag() == 0 || most_specific->get_offset() == 0UL)
			{
				// failed!
				cerr << "Static object discovery failed for " << (void*)addr << endl;
				return boost::shared_ptr<spec::with_static_location_die>();
			}
		}
	}
	return dynamic_pointer_cast<dwarf::spec::with_static_location_die>(most_specific);
}

} // end namespace pmirror
