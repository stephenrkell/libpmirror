#ifndef LIBCAKE_PROCESS_HPP
#define LIBCAKE_PROCESS_HPP

#include <string>
#include <map>
#include <set>
#include <functional>

#include <sys/types.h>
#include <unistd.h>

#include <link.h>

#include <boost/shared_ptr.hpp>
#include <boost/optional.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/iterator_adaptors.hpp>
#include <boost/icl/interval_map.hpp>

#include <gelf.h>

#include <dwarfpp/spec.hpp>
#include <dwarfpp/attr.hpp>
#include <dwarfpp/lib.hpp>
#include <dwarfpp/adt.hpp>

#ifndef NO_LIBUNWIND
#include <libunwind.h>
#include <libunwind-ptrace.h>
#else
/* libunwind substitues go here */
#include "fake-libunwind.h"
#endif

#include <srk31/algorithm.hpp> // from libsrk31c++
#include <srk31/concatenating_iterator.hpp>

extern "C" {
#include "objdiscover.h"
#include "addrmap.h"
}

#include "symbols.hpp"

#include "unw_read_ptr.hpp"
#include "unw_regs.hpp"

namespace pmirror
{

using namespace dwarf;
using boost::graph_traits;
using boost::shared_ptr;
using boost::dynamic_pointer_cast;
using boost::optional;
using dwarf::spec::type_die;
using dwarf::spec::with_named_children_die;
using dwarf::spec::with_static_location_die;
using dwarf::spec::with_dynamic_location_die;
using dwarf::spec::basic_die;
using dwarf::spec::subprogram_die;
using dwarf::spec::compile_unit_die;
using dwarf::lib::abstract_dieset;
using std::vector;
using std::string;
using std::pair;
using std::make_pair;
using std::map;
using std::multimap;
using boost::icl::interval_map;
using boost::icl::interval;

using srk31::concatenating_iterator;
using srk31::concatenating_sequence;

/* Utility function: search multiple diesets for the first 
 * DIE matching a predicate. */
shared_ptr<basic_die> resolve_first(
	vector<string> path,
	vector<shared_ptr<with_named_children_die> > starting_points,
	bool(*pred)(basic_die&) = 0);

/* We record the program break at startup, for memory kind detection. */
extern intptr_t startup_brk;

struct process_image
{
	typedef unw_word_t addr_t;
	static_assert(sizeof (addr_t) >= sizeof (void*), "address size is too small");

	/* We maintain a map of loaded objects, so that we can maintain
	 * a dieset open on each one. We must keep this map in sync with the
	 * actual process map. */
	typedef pair<addr_t, addr_t> entry_key;
	struct entry
	{
		char r, w, x, p;
		int offset;
		int maj, min;
		int inode;
		string seg_descr;
	};
	map<entry_key, entry> objects;
	typedef map<entry_key, entry>::iterator objects_iterator;

	/* We also maintain a map of canonicalised filenames
	 * to the handles we have open on them: 
	 * ifstream, a dwarf::lib::file and a dieset ptr. */
	struct file_entry
	{
		shared_ptr<std::ifstream> p_if;
		shared_ptr<lib::file> p_df;
		shared_ptr<abstract_dieset> p_ds;
		/* std::multimap<lib::Dwarf_Off, lib::Dwarf_Off> ds_type_containment; */
	};
	map<string, file_entry> files;
	typedef map<string, file_entry>::iterator files_iterator;
	
	/* To support DwarfPython and other use cases, the client can tell us
	 * that an anonymous segment actually has some associated DWARF information.
	 * These entries are stored in the files map too, although with null p_if. 
	 * For each such registered segment, we record its DWARF base address, 
	 * i.e. this need not correspond to the segment base address.
	 * This is because addresses are absolute (process-relative) in DwarfPython diesets. */
	map<addr_t, addr_t> anon_segments_dwarf_bases;
	// FIXME: we currently ignore the .second of these pairs -- just using it
	// to track the known anonymous mappings
public:
	void register_anon_segment_description(addr_t base, 
		shared_ptr<abstract_dieset> p_ds,
		addr_t base_for_dwarf_info);
	void 
	register_range_as_dieset(addr_t begin, addr_t end, 
		shared_ptr<abstract_dieset> p_ds);
private:
	
	static const char *ANONYMOUS_REGION_FILENAME;
private:
	pid_t m_pid;   /* always set to the current pid */
	bool is_local; /* whether m_pid == getpid() */
	
	unw_addr_space_t unw_as;
	unw_accessors_t unw_accessors;
	void *unw_priv;
	unw_context_t unw_context;

#ifndef NO_DL_ITERATE_PHDR
	r_debug rdbg;
#endif

	/* The contents of /proc/<m_pid>/maps the last time we looked. */
	vector<string> seen_map_lines;
	files_iterator i_executable; // points to the files entry representing the executable
	Elf *executable_elf; // an ELF handle on the executable
	bool is_statically_linked; // whether the executable is static-linked
	
	// FIXME: bring this heap metadata up-to-date with the memtable-based implementation
	/* static const char *alloc_list_symname; */
	static const char *alloc_list_lib_basename;
	addr_t alloc_list_head_ptr_addr; // base address of data structure holding heap metadata

	/* Query the files and objects maps. */
public:
	/* Lookup a file in the files map, given a possibly *non*-canonical filename. */
	map<string, file_entry>::iterator find_file_by_realpath(
		const string& path,
		optional<map<string, file_entry>::iterator> begin_here = 
			optional<map<string, file_entry>::iterator>()
	);
	
	addr_t get_dieset_base(abstract_dieset& ds);
	addr_t get_library_base(const string& path);

	objects_iterator find_object_for_addr(unw_word_t addr);
	files_iterator find_file_for_addr(unw_word_t addr);
	
	/* Query deeper static structure, using DWARF info. */
public:
	shared_ptr<basic_die> find_first_matching(
		bool(*pred)(shared_ptr<basic_die>, void *pred_arg), void *pred_arg);

private:
	struct interval_descriptor
	{
		enum { DWARF_DESCRIPTOR, ELF_DESCRIPTOR } kind;
		// union
		// {
			symbols_iterator elf_sym;
			abstract_dieset::position_and_path dwarf_die;
		// };
		
		interval_descriptor(const symbols_iterator& sym)
		 : kind(ELF_DESCRIPTOR), elf_sym(sym),
			dwarf_die() {}
		interval_descriptor()
		 : kind(ELF_DESCRIPTOR), elf_sym(),
			dwarf_die() {}
		bool operator==(const interval_descriptor& arg) const
		{ return kind == arg.kind
			&& ((kind == ELF_DESCRIPTOR)
					? elf_sym == arg.elf_sym
					: dwarf_die == arg.dwarf_die);
		}
	};
	// FIXME: split into "ELF intervals" (linker-level)
	// and "DWARF intervals" (source-level)
	// -- if we want both views (rare) we can do two queries
	interval_map<addr_t, interval_descriptor> intervals;
	// HACK: while intervals is behaving strangely
	map<addr_t, const char * > addr_to_sym_map;

	/* FIXME: remove this once we have the interval tree to replace it. */
	typedef map< 
		pair< 
			abstract_dieset::position_and_path, 
			addr_t 
		>,
		abstract_dieset::position_and_path 
	> location_refinements_cache_t;
	location_refinements_cache_t location_refinements_cache;
public:
	
	/* Single-step lookup. */
	abstract_dieset::iterator
	find_more_specific_die_for_dieset_relative_addr(
		abstract_dieset::iterator under_here,
		unw_word_t addr);
	
	/* DIE-predicated lookup of absolute addresses. */
	// FIXME: there is a non-template function of the same name below...
	template <typename Pred>
	shared_ptr<with_static_location_die> 
	find_containing_die_for_absolute_addr(
		unw_word_t addr,
		const Pred& pred,
		bool innermost,
		optional<abstract_dieset::iterator> start_here = optional<abstract_dieset::iterator>());

	/* DIE-predicated lookup of relative addresses. */
	template <typename Pred>
	shared_ptr<with_static_location_die> 
	find_containing_die_for_dieset_relative_addr(
		abstract_dieset& ds,
		lib::Dwarf_Off dieset_relative_addr, 
		const Pred& pred,
		bool innermost,
		optional<abstract_dieset::iterator> start_here = optional<abstract_dieset::iterator>());

	shared_ptr<subprogram_die> 
	find_subprogram_for_absolute_ip(unw_word_t ip);
	
	shared_ptr<compile_unit_die> 
	find_compile_unit_for_absolute_ip(unw_word_t ip);

	abstract_dieset::iterator // the same, but find an iterator suitable for start_here arg
	cu_iterator_for_absolute_ip(unw_word_t ip);
	
	abstract_dieset::iterator
	cu_iterator_for_dieset_relative_addr(
		files_iterator i_file,
		addr_t dieset_relative_addr);
	
	shared_ptr<with_static_location_die> 
	find_containing_die_for_absolute_addr(unw_word_t addr, bool innermost);
	
	shared_ptr<with_static_location_die> 
	find_most_specific_die_for_absolute_addr(addr_t addr)
	{ return find_containing_die_for_absolute_addr(addr, true); }
	
	/* Query static or dynamic structure, using DWARF info. */
public:
	/* Discover the address of a program element given its DWARF info. */
	addr_t 
	get_object_from_die(shared_ptr<with_static_location_die> d,
		lib::Dwarf_Addr vaddr);
	
	/* Discover the DWARF type of a program element (perhaps dynamic) given its address. */
	shared_ptr<basic_die> 
	discover_object_descr(addr_t addr,
		shared_ptr<type_die> imprecise_static_type
		 = shared_ptr<type_die>(),
		addr_t *out_object_start_addr = 0);

	/* Discover the DWARF description of a static program object given its address. */
	shared_ptr<with_static_location_die> 
	discover_object(
		addr_t addr,
		addr_t *out_object_start_addr);

	/* Construction, update and destruction. */
public:
	process_image(pid_t pid = -1);
	~process_image() { if (executable_elf) elf_end(executable_elf); }
	
	/* Re-scan for changes to the process's mappings. */
	void update();
private:
	bool rebuild_map();
	void update_rdbg();
	void update_i_executable();
	void update_executable_elf();
	void update_intervals();

	/* Classifying pointers by storage kind. */
public:
	typedef ::object_memory_kind memory_kind;
private:
	// slow but complete version
	memory_kind discover_object_memory_kind_from_maps(addr_t addr) const;
public:
	static const char *name_for_memory_kind(/*memory_kind*/ int k); // relaxation for ltrace++

	memory_kind discover_object_memory_kind(addr_t addr) const
	{
		if (is_local)
		{
			memory_kind retval = get_object_memory_kind((void*) addr);
			if (retval != UNKNOWN) return retval;
			// we have one trick left: use sbrk, which can rule out static
			// BUT only if we have a reliable end, without which we won't
			// have detected STATIC cases in get_object_memory_kind
			if (end != 0 && addr < (unsigned long) sbrk(0)) return HEAP;
			// to handle the "end == 0" case, we also grab the sbrk(0) at startup
			if (addr < startup_brk) return STATIC;
			if (end == 0 && addr >= startup_brk && addr < (unsigned long) sbrk(0)) return HEAP;
			// otherwise, fall through
			cerr << "Warning: falling back on maps to identify " 
				<< std::hex << addr << std::dec
				<< " as heap or static storage." << endl;
		}
		// fall back on the maps version
		return discover_object_memory_kind_from_maps(addr);
	}

	/* Reading the dynamic linker map. */
private:
	// typedefs for accessing the link map in the target process
	typedef unw_read_ptr<link_map> lm_ptr_t;
	typedef unw_read_ptr<char> remote_char_ptr_t;

	addr_t get_library_base_local(const string& path);
	addr_t get_library_base_remote(const string& path);
	addr_t get_library_base_from_maps(const string& path);

	// equivalence classes of data types -- 
	// since according to our current definition, equivalent types always share
	// a list of idents below the CU level
	// (and we don't expect these to recur, although they theoretically could),
	// make this a map from these ident lists to sets of abstract_dieset::positions
		/* void update_master_type_containment();
	void update_master_type_equivalence();
	
	virtual bool type_equivalence(shared_ptr<type_die> t1,
		shared_ptr<type_die> t2);
	
	void write_type_containment_relation(
		multimap<lib::Dwarf_Off, lib::Dwarf_Off>& out_mm,
		spec::abstract_dieset& ds); */
public:
	/* Try to produce a human-readable representation of an object. */
	std::ostream& print_object(std::ostream& s, void *obj) const;

	/* Stack walking. */
public:
	shared_ptr<with_dynamic_location_die> 
	discover_stack_object(addr_t addr,
		addr_t *out_object_start_addr,
		addr_t *out_frame_base,
		addr_t *out_frame_return_addr
	);
	
	typedef int (*stack_frame_cb_t)(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_caller_ip,
		unw_word_t frame_callee_ip,
		unw_cursor_t frame_cursor,
		unw_cursor_t frame_callee_cursor,
		void *arg);
	int walk_stack(void *stack_handle, stack_frame_cb_t handler, void *handler_arg);
	

private:
	shared_ptr<with_dynamic_location_die> 
	discover_stack_object_local(
		addr_t addr, 
		addr_t *out_object_start_addr,
		addr_t *out_frame_base,
		addr_t *out_frame_return_addr
	);
		
	shared_ptr<with_dynamic_location_die> 
	discover_stack_object_remote(
		addr_t addr, 
		addr_t *out_object_start_addr,
		addr_t *out_frame_base,
		addr_t *out_frame_return_addr
	);
	
	/* Heap query. */
public:
	/* Clients can tell us the DWARF type of arbitrary objects,
	 * overriding whatever we thought was there,
	 * for subsequent calls to discover_object_descr. */
	void 
	inform_heap_object_descr(
		addr_t addr,
		shared_ptr<type_die>);
private:
	map<addr_t, shared_ptr<type_die> > informed_heap_descrs;

	shared_ptr<basic_die> 
	discover_heap_object(addr_t addr,
		shared_ptr<type_die> imprecise_static_type,
		addr_t *out_object_start_addr);
		
	shared_ptr<basic_die>
	discover_heap_object_local(addr_t addr,
		shared_ptr<type_die> imprecise_static_type,
		addr_t *out_object_start_addr);
		
	shared_ptr<basic_die> 
	discover_heap_object_remote(addr_t addr,
		shared_ptr<type_die> imprecise_static_type,
		addr_t *out_object_start_addr);

	/* Symbols and linker-related functions. */
public:
#ifndef NO_DL_ITERATE_PHDR
	std::pair<GElf_Shdr, GElf_Phdr> get_static_memory_elf_headers(addr_t addr);
	/* We want this to help us handle the case of unwinding a call 
	 * routed through the PLT, which will sometimes give bad unwind info.
	 * For now, it doesn't work. */
	bool is_linker_code(addr_t addr)
	{	
		auto kind = get_static_memory_elf_headers(addr);
		return kind.first.sh_type == SHT_PROGBITS // FIXME: this is WRONG!
		 && kind.second.p_type == PT_LOAD
		 && (kind.second.p_flags & PF_X);
	}
#endif

	typedef with_static_location_die::sym_binding_t sym_binding_t;
	// ^-- this is a pair: file-relative symbol start addr, and symbol size
	
	bool  
	nearest_preceding_symbol(addr_t addr,
		string *out_sym_name,
		addr_t *out_sym_start,
		size_t *out_sym_size,
		string *out_object_fname
	);
	
	// NOTE: this makes a great example of lightweight data abstraction!
	// We want symbols_iterator to inherit the concepts of esym,
	// but we've added an extra field for destruction logic.
	// Maybe iterator_adapter is a more general case study
	pair<symbols_iterator, symbols_iterator> symbols(process_image::files_iterator& i,
		Elf64_Word sh_type = SHT_DYNSYM)
	{
		Elf *e = 0;
		if (i->second.p_df) { i->second.p_df->get_elf(&e); }
		// if we have no df, e will be null and we will get an empty sequence
		auto p_priv = boost::make_shared<symbols_iteration_state>(e, sh_type);
		symbols_iterator begin((symbols_iterator_base){ 0 }, p_priv);
		symbols_iterator end((symbols_iterator_base){ p_priv->symcount }, p_priv);
		return make_pair(begin, end);
	}
	pair<
		concatenating_iterator<symbols_iterator>,
		concatenating_iterator<symbols_iterator>
	>
	static_symbols(process_image::files_iterator& i)
	{
		//return symbols(i, SHT_SYMTAB);
		typedef concatenating_iterator<symbols_iterator> all_symbols_sequence;
		auto p_seq = boost::make_shared< concatenating_sequence<symbols_iterator> >();
		auto static_syms = symbols(i, SHT_SYMTAB);
		p_seq->append(static_syms.first, static_syms.second);
		return make_pair(p_seq->begin(), p_seq->end());
	}
	pair<
		concatenating_iterator<symbols_iterator>,
		concatenating_iterator<symbols_iterator>
	>
	dynamic_symbols(process_image::files_iterator& i)
	{
		typedef concatenating_iterator<symbols_iterator> all_symbols_sequence;
		auto p_seq = boost::make_shared< concatenating_sequence<symbols_iterator> >();
		auto dynamic_syms = symbols(i, SHT_DYNSYM);
		p_seq->append(dynamic_syms.first, dynamic_syms.second);
		return make_pair(
			p_seq->begin(/*p_seq*/),
			p_seq->end(/*p_seq*/)
		);
	}
	pair<
		concatenating_iterator<symbols_iterator>,
		concatenating_iterator<symbols_iterator>
	> 
	all_symbols(process_image::files_iterator& i)
	{
		typedef concatenating_iterator<symbols_iterator> all_symbols_sequence;
		auto p_seq = boost::make_shared< concatenating_sequence<symbols_iterator> >();
		auto dynamic_syms = symbols(i, SHT_SYMTAB);
		auto static_syms = symbols(i, SHT_DYNSYM);
		p_seq->append(dynamic_syms.first, dynamic_syms.second);
		p_seq->append(static_syms.first, static_syms.second);
		return make_pair(
			p_seq->begin(/*p_seq*/),
			p_seq->end(/*p_seq*/)
		);
		
	}
};

/* Stack walking callbacks and their argument. */
int stack_print_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_caller_ip,
		unw_word_t frame_callee_ip,
		unw_cursor_t frame_cursor,
		unw_cursor_t frame_callee_cursor,
		void *arg);
int stack_object_discovery_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_caller_ip,
		unw_word_t frame_callee_ip,
		unw_cursor_t frame_cursor,
		unw_cursor_t frame_callee_cursor,
		void *arg);
struct stack_object_discovery_handler_arg
{
	// in
	process_image::addr_t addr;
	// out
	shared_ptr<with_dynamic_location_die> discovered_die;
	process_image::addr_t object_start_addr;
	process_image::addr_t frame_base;
	process_image::addr_t frame_return_addr;
};

typedef process_image::addr_t addr_t;

process_image::sym_binding_t resolve_symbol_from_process_image(
	const string& sym, void *p_pair);

std::ostream& operator<<(std::ostream& s, const process_image::memory_kind& k);

} // end namespace pmirror

#endif
