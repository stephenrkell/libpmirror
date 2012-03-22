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
	auto result = srk31::greatest_le(
		addr_to_sym_map.begin(),
		addr_to_sym_map.end(),
		make_pair(addr, (const char *) 0),
		addr_to_sym_map.value_comp()
	);
	if (result != addr_to_sym_map.end())
	{
		*out_sym_name = result->second ? string(result->second) : string();
		assert(!out_sym_start);
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
        return files.end();
    }
}


dwarf::lib::abstract_dieset::position_and_path
process_image::find_more_specific_die_for_dieset_relative_addr(
	dwarf::lib::abstract_dieset::position_and_path under_here,
	unw_word_t dieset_relative_addr)
{
	unsigned initial_depth = under_here.path_from_root.size();
	auto initial_under_here = under_here;
	
	dwarf::spec::abstract_dieset& ds = *under_here.p_ds;

	/* Try the cache... */
	location_refinements_cache_t::iterator found;
	if (
		(found = 
			location_refinements_cache.find(
				make_pair(
					under_here,
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
			assert(found->second.off != under_here.off);
			return found->second;
		}
	}
	// else run the slow path

	std::cerr << "*** search for more specific match for dieset relative addr 0x" 
		<< std::hex << dieset_relative_addr << std::hex
		<< " than DIE at offset 0x" 
		<< std::hex << (*initial_under_here.p_ds)[initial_under_here.off]->get_offset() 
		<< std::dec << std::endl;
	
	
	//dwarf::spec::abstract_dieset::bfs_policy bfs_state;
	
	/* We use two optimisations in this function, to avoid searching huge
	 * numbers of DIEs at each call.
	 * 
	 * 1. Cache returned mappings: (under_here, addr) --> there
	 * 
	 * 2. Instead of straight BFS, we want a modification: don't bother
	 * descending into subtrees that will not contain any  */
	 
	struct location_subtree_policy :  public dwarf::spec::abstract_dieset::bfs_policy
	{
		typedef dwarf::spec::abstract_dieset::bfs_policy super;
		int increment(dwarf::spec::abstract_dieset::position& pos,
			dwarf::spec::abstract_dieset::path_type& path)
		{
			/* If our current DIE is 
			 * a with_static_location_die
			 * OR
			 * is in the "interesting set"
			 * of DIEs that have no location but might contain such DIEs,
			 * we increment *with* enqueueing children.
			 * Otherwise we increment without enqueueing children.
			 */
			auto p_die = (*pos.p_ds)[pos.off];
			if (dynamic_pointer_cast<dwarf::spec::with_static_location_die>(p_die))
			{
				return super::increment(pos, path);
			}
			else
			{
				switch (p_die->get_tag())
				{
					case DW_TAG_namespace:
					case DW_TAG_module:
					case DW_TAG_imported_unit:
					case DW_TAG_imported_module:
					case DW_TAG_partial_unit:
					case DW_TAG_common_block:
					case DW_TAG_common_inclusion:
						return super::increment(pos, path);
						break;
					default:
						return super::increment_skipping_subtree(pos, path);
						break;
				}
			}
		}
	} search_state;
	
	dwarf::spec::abstract_dieset::iterator depthfirst_i(under_here);
	depthfirst_i++; // now we have the first child, or something higher
	dwarf::spec::abstract_dieset::iterator i(depthfirst_i, search_state);
	for (; i != ds.end() && i.base().path_from_root.size() > initial_depth; i++)
	{
		unsigned depth = i.base().path_from_root.size();
		
// 		std::cerr << "*** considering " 
// 			<< (*i)->get_spec().tag_lookup((*i)->get_tag())
// 			<< " at 0x"
// 			<< std::hex << (*i)->get_offset() << std::dec << std::endl;
// 			//<< std::hex << i << std::endl;
		auto p_has_location = dynamic_pointer_cast<spec::with_static_location_die>(*i);
		if (p_has_location && p_has_location->contains_addr(dieset_relative_addr))
		{
			std::cerr << "*** found more specific match, "
				<< (*i)->get_spec().tag_lookup((*i)->get_tag())
				<< " at 0x"
				<< std::hex << (*i)->get_offset() << std::dec
				<< ", for dieset-relative addr 0x" 
				<< std::hex << dieset_relative_addr << std::hex
				<< " (than DIE at offset 0x" 
				<< std::hex << initial_under_here.off << std::dec << ")"
				/*<< ": " << *p_has_location*/ << std::endl;
				
			// add to cache
			location_refinements_cache.insert(
				make_pair(
					make_pair(
						under_here,
						dieset_relative_addr
					),
					i.base()
				)
			);
			
			// return
			return i.base();
		}
		//else std::cerr << (p_has_location ? "no static location" : "does not contain addr") << std::endl;
	}
	std::cerr << "*** no more specific match for dieset-relative addr 0x" 
		<< std::hex << dieset_relative_addr << std::hex
		<< " (than DIE at offset 0x" << std::hex << initial_under_here.off << std::dec
		<< std::endl;
	
	// add negative result to cache
	location_refinements_cache.insert(
		make_pair(
			make_pair(
				under_here,
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
	return dynamic_pointer_cast<spec::subprogram_die>(
		find_containing_die_for_absolute_addr(
			ip,
			[](const basic_die& d) { return d.get_tag() == DW_TAG_subprogram; }, // pred
			false // innermost? no, outermost should be fine (BUT nested subprograms?)
		));
}
shared_ptr<compile_unit_die> 
process_image::find_compile_unit_for_absolute_ip(unw_word_t ip)
{
	return dynamic_pointer_cast<spec::compile_unit_die>(
		find_containing_die_for_absolute_addr(
			ip,
			[](const basic_die& d) { return d.get_tag() == DW_TAG_compile_unit; }, // pred
			false // innermost? no, outermost should be fine
		));
}
shared_ptr<with_static_location_die> 
process_image::find_containing_die_for_absolute_addr(unw_word_t addr, bool innermost)
{
	auto retval = dynamic_pointer_cast<spec::with_static_location_die>(
		find_containing_die_for_absolute_addr(
			addr,
			[](const basic_die& d) { return true; }, // pred
			innermost // innermost?
		));
	assert(retval); // cast should not fail
	return retval;
}
// implementation of the above
template <typename Pred>
shared_ptr<with_static_location_die> 
process_image::find_containing_die_for_absolute_addr(
	unw_word_t addr,
	const Pred& pred,
	bool innermost)
{
	process_image::files_iterator found_file = find_file_for_addr(addr);
	assert (found_file != this->files.end());
	dwarf::spec::abstract_dieset& ds = *found_file->second.p_ds;
	unw_word_t dieset_relative_addr = addr - get_dieset_base(ds);

	auto found = find_containing_die_for_dieset_relative_addr(
			ds,
			dieset_relative_addr,
			pred, // pred
			innermost // innermost?
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
	dwarf::spec::abstract_dieset& ds,
	Dwarf_Off dieset_relative_addr, 
	const Pred& pred,
	bool innermost)
{
	auto under_here = ds.toplevel()->iterator_here();
	dwarf::spec::abstract_dieset::position_and_path found_deeper = under_here.base();
	dwarf::spec::abstract_dieset::position_and_path last_to_satisfy = ds.end().base();
	while (found_deeper != ds.end().base())
	{
		if (pred(*(*found_deeper.p_ds)[found_deeper.off]))
		{
			last_to_satisfy = found_deeper;
			if (!innermost) break;
			// else continue searching
		}
		
		// try to go lower
		found_deeper = find_more_specific_die_for_dieset_relative_addr(
			found_deeper,
			dieset_relative_addr);
	}
	if (last_to_satisfy == ds.end().base()) return shared_ptr<with_static_location_die>();
	else
	{
		auto found = (*last_to_satisfy.p_ds)[last_to_satisfy.off];
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
