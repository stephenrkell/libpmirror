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
using std::shared_ptr;

using dwarf::spec::basic_die;
using dwarf::spec::subprogram_die;
using dwarf::spec::type_die;
using dwarf::spec::variable_die;
using dwarf::spec::with_static_location_die;
using dwarf::spec::compile_unit_die;

process_image::process_image(pid_t pid /* = -1 */)
#ifndef NO_LIBUNWIND 
	: 	m_pid(pid == -1 ? getpid() : pid),
		is_local(m_pid == getpid()), /* so can pass either -1 or our own pid */
		is_statically_linked(false),
		unw_as(is_local ? 
		unw_local_addr_space : 
		unw_create_addr_space(&_UPT_accessors/*&unw_accessors*/, 0)),
#else /* special versions */
	:	m_pid((assert(pid == -1), getpid())),
		is_local(true),
		is_statically_linked(false),
		unw_as(unw_local_addr_space),
#endif
		executable_elf(((Elf*)0))/*,
		master_type_containment(*this)*/
{
	int retval = unw_getcontext(&unw_context);
	assert(retval == 0);
	if (is_local)
	{
		unw_accessors = *unw_get_accessors(unw_local_addr_space);
		unw_priv = 0;
	}
	else 
	{
#ifndef NO_LIBUNWIND
		unw_accessors = _UPT_accessors;
		unw_priv = _UPT_create(m_pid);
#else
		assert(false);
#endif
	}
	update();
}
//process_image::process_image(pid_t pid) {}

/* Utility function: search multiple diesets for the first 
 * DIE matching a predicate. */
std::shared_ptr<spec::basic_die> resolve_first(
    std::vector<string> path,
    std::vector<std::shared_ptr<spec::with_named_children_die > > starting_points,
    bool(*pred)(spec::basic_die&) /*=0*/)
{
	for (auto i_start = starting_points.begin(); i_start != starting_points.end(); ++i_start)
    {
    	std::vector<std::shared_ptr<spec::basic_die> > results;
        (*i_start)->scoped_resolve_all(path.begin(), path.end(), results);
        for (auto i_result = results.begin(); i_result != results.end(); ++i_result)
        {
        	assert(*i_result); // result should not be null ptr
			std::cerr << "Considering result " << **i_result << std::endl;
        	if (!pred || pred(**i_result)) return *i_result;
		}
    }
	return std::shared_ptr<spec::basic_die>();
}

std::shared_ptr<dwarf::spec::basic_die> 
process_image::find_first_matching(
		bool(*pred)(std::shared_ptr<dwarf::spec::basic_die>, void *pred_arg),
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
  std::shared_ptr<spec::with_static_location_die> p_d, 
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
