#include "process.hpp"
#include <fstream>
#include <sstream>
#include <climits>
#include <cstdio>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cstring> /* for basename(), among other things -- must be the GNU version */
#include <fileno.hpp>
//#define _GNU_SOURCE
#include <link.h>
#include <gelf.h>
#include <malloc.h>


/* FIXME: currently we rely too much on manual updates of the memory map. 
 * We should really trap every event that changes the memory map
 * (dlopen(), mmap(), sbrk(), ...) 
 * and then dispense with the updates. */

extern "C" {
#include "heap_index.h"
}

#ifndef ELF_MAX_SEGMENTS
#define ELF_MAX_SEGMENTS 50
#endif

#include <srk31/ordinal.hpp>

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

using srk31::conjoining_iterator;
using srk31::conjoining_sequence;

using dwarf::spec::basic_die;
using dwarf::spec::subprogram_die;
using dwarf::spec::type_die;
using dwarf::spec::variable_die;
using dwarf::spec::with_static_location_die;
using dwarf::spec::compile_unit_die;


/* Utility function: search multiple diesets for the first 
 * DIE matching a predicate. */
boost::shared_ptr<spec::basic_die> resolve_first(
    std::vector<string> path,
    std::vector<boost::shared_ptr<spec::with_named_children_die > > starting_points,
    bool(*pred)(spec::basic_die&) /*=0*/)
{
	for (auto i_start = starting_points.begin(); i_start != starting_points.end(); ++i_start)
    {
    	std::vector<boost::shared_ptr<spec::basic_die> > results;
        (*i_start)->scoped_resolve_all(path.begin(), path.end(), results);
        for (auto i_result = results.begin(); i_result != results.end(); ++i_result)
        {
        	assert(*i_result); // result should not be null ptr
			std::cerr << "Considering result " << **i_result << std::endl;
        	if (!pred || pred(**i_result)) return *i_result;
		}
    }
	return boost::shared_ptr<spec::basic_die>();
}

boost::shared_ptr<dwarf::spec::basic_die> 
process_image::find_first_matching(
		bool(*pred)(boost::shared_ptr<dwarf::spec::basic_die>, void *pred_arg),
		void *pred_arg)
{
	for (auto i_file = files.begin(); i_file != files.end(); ++i_file)
	{
		if (i_file->second.p_ds)
		{
			for (auto i_die = i_file->second.p_ds->begin(); i_die != i_file->second.p_ds->end(); ++i_die)
			{
				auto die_ptr = (*i_file->second.p_ds)[i_die.base().off];
				if (pred(die_ptr, pred_arg))
				{
					return die_ptr;
				}
			}
		}
	}
}

process_image::addr_t 
process_image::get_object_from_die(
  boost::shared_ptr<spec::with_static_location_die> p_d, 
  lib::Dwarf_Addr vaddr)
{
	/* From a DIE, return the address of the object it denotes. 
     * This only works for DIEs describing objects existing at
     * runtime. */

	unsigned char *base = reinterpret_cast<unsigned char *>(get_dieset_base(p_d->get_ds()));
    assert(p_d->get_static_location().size() == 1);
    auto loc_expr = p_d->get_static_location();
    lib::Dwarf_Unsigned result = dwarf::lib::evaluator(
        loc_expr,
        vaddr,
        p_d->get_spec()
        ).tos();
    unsigned char *retval = base + static_cast<size_t>(result);
    return reinterpret_cast<addr_t>(retval);
}

} // end namespace pmirror
