#include "process.hpp"
#include <fstream>
#include <sstream>
#include <fileno.hpp>
#include <link.h>
#include <gelf.h>

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

// constructor
process_image::symbols_iteration_state::symbols_iteration_state
(const process_image::files_iterator& i, Elf64_Word sh_type /* = SHT_DYNSYM */)
{
    /* process_image::files_iterator *p_file_iterator
     = reinterpret_cast<process_image::files_iterator *>(p_file_iterator_void);
	(*p_file_iterator)->second.p_df->get_elf(&elf);*/

	if (!i->second.p_df)
	{
		firstsym = lastsym = 0;
		elf = 0;
		return;
	}
	
	i->second.p_df->get_elf(&elf);

	// code gratefully stolen from Sun libelf docs
	scn = 0;
	int number = 0;
	while ((scn = elf_nextscn(elf, scn)) != 0) 
	{
		char *name = 0;
		if (gelf_getshdr (scn, &shdr) != 0) 
		{
			if (shdr.sh_type == sh_type) 
			{
				char *name;
				char *stringName;
				data = 0;
				int number = 0;
				if ((data = elf_getdata(scn, data)) == 0 || data->d_size == 0)
				{
					throw dwarf::lib::No_entry(); // FIXME: better choice of exception
				}
				/* now print the symbols */
				firstsym = data->d_buf;
				lastsym = (char*) data->d_buf + data->d_size;
				//cerr << "First symbol is at " << firstsym << ", last at " << lastsym << endl;
				//cerr << "Strtab section has index " << shdr.sh_link << endl;
				symcount = shdr.sh_size / shdr.sh_entsize;
				//cerr << "Symtab has " << symcount << "symbols." << endl;
				return;
			}
		}
	}
	firstsym = lastsym = 0;
}
	
process_image::symbols_iteration_state::~symbols_iteration_state()
{
	// FIXME: do we really not have any ELF cleanup to do? 
	// get_elf() needs no release_elf()?
}

process_image::sym_binding_t resolve_symbol_from_process_image(
	const std::string& sym, /*process_image::files_iterator * */ void *p_pair_void)
{
    auto p_pair
     = reinterpret_cast<
	 	std::pair<process_image *, process_image::files_iterator> *>(p_pair_void);
	auto syms = p_pair->first->symbols(p_pair->second);
	
	for (auto i_sym = syms.first; i_sym != syms.second; ++i_sym)
	{
		if ((i_sym->st_value == 0) ||
			(GELF_ST_BIND(i_sym->st_info)== STB_WEAK) ||
			(GELF_ST_BIND(i_sym->st_info)== STB_NUM) ||
			(
				(GELF_ST_TYPE(i_sym->st_info)!= STT_FUNC)
				&& (GELF_ST_TYPE(i_sym->st_info)!= STT_OBJECT)
				&& (GELF_ST_TYPE(i_sym->st_info)!= STT_COMMON) // FIXME: support TLS
			)
		) continue;
		auto name = elf_strptr(i_sym.origin->elf, i_sym.origin->shdr.sh_link , 
			(size_t)i_sym->st_name);
		if(!name)
		{
			// null symbol name

			//fprintf(stderr,"%sn",elf_errmsg(elf_errno()));
			//exit(-1);
			throw dwarf::lib::No_entry(); // FIXME: better choice of exception
		}
		else if (sym == std::string(name))
		{
			process_image::sym_binding_t binding;
			binding.file_relative_start_addr = i_sym->st_value;
			binding.size = i_sym->st_size;
			return binding;
		}
		//printf("%d: %sn",number++, name);
    }
	/* not found! */
	throw dwarf::lib::No_entry();
}

} // end namespace pmirror
