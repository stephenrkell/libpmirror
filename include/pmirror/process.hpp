#ifndef LIBCAKE_PROCESS_HPP
#define LIBCAKE_PROCESS_HPP

#include <string>
#include <map>
#include <set>
#include <functional>

#include <sys/types.h>

#include <link.h>

#include <boost/shared_ptr.hpp>
#include <boost/optional.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/iterator_adaptors.hpp>

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

using srk31::concatenating_iterator;
using srk31::concatenating_sequence;

/* Utility function: search multiple diesets for the first 
 * DIE matching a predicate. */
shared_ptr<basic_die> resolve_first(
    vector<string> path,
    vector<shared_ptr<with_named_children_die> > starting_points,
    bool(*pred)(basic_die&) = 0);

struct process_image
{
	/* We maintain a map of loaded objects, so that we can maintain
     * a dieset open on each one. We must keep this map in sync with the
     * actual process map. */
    typedef unw_word_t addr_t;
	static_assert(sizeof (addr_t) >= sizeof (void*), "address size is too small");
	typedef pair<addr_t, addr_t> entry_key;
    
    static const char *ANONYMOUS_REGION_FILENAME;

    struct entry
    {
        char r, w, x, p;
        int offset;
        int maj, min;
        int inode;
        string seg_descr;
    };
//     enum memory_kind
//     {
// 	    UNKNOWN,
//         STACK,
//         HEAP,
//         STATIC,
//         ANON
//     };
	static const char *name_for_memory_kind(/*memory_kind*/ int k); // relaxation for ltrace++
    
    struct file_entry
    {
		shared_ptr<std::ifstream> p_if;
		shared_ptr<lib::file> p_df;
		shared_ptr<abstract_dieset> p_ds;
		/* std::multimap<lib::Dwarf_Off, lib::Dwarf_Off> ds_type_containment; */
    };
    
	map<entry_key, entry> objects;
    typedef map<entry_key, entry>::iterator objects_iterator;
    map<string, file_entry> files;
    typedef map<string, file_entry>::iterator files_iterator;
    
    /* For each registered file that is an [anon] segment, we record its
     * DWARF address separately. This is because addresses are process-relative
     * in DwarfPython diesets. */
    map<addr_t, addr_t> anon_segments_dwarf_bases;
    // FIXME: we currently ignore the .second of these pairs -- just using it
    // to track the known anonymous mappings
    
    /* Problem: all addresses could have i_file be the executable;
     * do we want to support i_file being libraries too? Do we want
     * a single vaddr to have multiple section_ and segment_addresses? */
    struct section_address
    { 
    	files_iterator i_file;
        string section_name;
        GElf_Off offset; // offset in file? or in vaddr-space defined by ELF file?
    };
    struct segment_address
    { 
    	files_iterator i_file;
        string segment_name;
        GElf_Off offset; // offset in file? or in vaddr-space defined by ELF file?
    };

private:
	pid_t m_pid;
	bool is_local;
	unw_addr_space_t unw_as;
	unw_accessors_t unw_accessors;
	void *unw_priv;
	unw_context_t unw_context;
#ifndef NO_DL_ITERATE_PHDR
	r_debug rdbg;
#endif
	vector<string> seen_map_lines;
	files_iterator i_executable; // points to the files entry representing the executable
	
	static const char *alloc_list_lib_basename;
	/* static const char *alloc_list_symname; */
	addr_t alloc_list_head_ptr_addr; // base address of data structure holding heap metadata

	Elf *executable_elf;
	// equivalence classes of data types -- 
	// since according to our current definition, equivalent types always share
	// a list of idents below the CU level
	// (and we don't expect these to recur, although they theoretically could),
	// make this a map from these ident lists to sets of abstract_dieset::positions
	
	/* A cache of the location */
	typedef map< 
		pair< 
			abstract_dieset::position_and_path, 
			addr_t 
		>,
		abstract_dieset::position_and_path 
	> location_refinements_cache_t;
	location_refinements_cache_t location_refinements_cache;
	
	abstract_dieset::position_and_path
	find_more_specific_die_for_dieset_relative_addr(
		abstract_dieset::position_and_path under_here,
    	unw_word_t addr);
		
	template <typename Pred>
	shared_ptr<with_static_location_die> 
	find_containing_die_for_absolute_addr(
		unw_word_t addr,
		const Pred& pred,
		bool innermost);
	template <typename Pred>
	shared_ptr<with_static_location_die> 
	find_containing_die_for_dieset_relative_addr(
		abstract_dieset& ds,
		lib::Dwarf_Off dieset_relative_addr, 
		const Pred& pred,
		bool innermost);

public:
	shared_ptr<subprogram_die> 
	find_subprogram_for_absolute_ip(unw_word_t ip);
	
	shared_ptr<compile_unit_die> 
	find_compile_unit_for_absolute_ip(unw_word_t ip);
	
	shared_ptr<with_static_location_die> 
	find_containing_die_for_absolute_addr(unw_word_t addr, bool innermost);
	
    shared_ptr<with_static_location_die> 
	find_most_specific_die_for_absolute_addr(addr_t addr)
	{ return find_containing_die_for_absolute_addr(addr, true); }

    process_image(pid_t pid = -1);
    void update();
    ~process_image() { if (executable_elf) elf_end(executable_elf); }
    
	map<string, file_entry>::iterator find_file_by_realpath(
		const string& path,
		optional<map<string, file_entry>::iterator> begin_here = 
			optional<map<string, file_entry>::iterator>()
	);
	
	typedef ::object_memory_kind memory_kind;
	memory_kind discover_object_memory_kind(addr_t addr) const
	{ assert(is_local); // FIXME: remote implementation has gone away temporarily
	  return get_object_memory_kind((void*) addr);
	}
	// slower version using maps info
	memory_kind discover_object_memory_kind_from_maps(addr_t addr) const;
	
    addr_t get_dieset_base(abstract_dieset& ds);
    addr_t get_library_base(const string& path);

    void register_anon_segment_description(addr_t base, 
        shared_ptr<abstract_dieset> p_ds,
        addr_t base_for_dwarf_info);

	typedef with_static_location_die::sym_binding_t sym_binding_t;
    //sym_binding_t resolve_symbol(files_iterator file, const string& sym);
	//sym_binding_t resolve_symbol(
	//	const string& sym, void *p_file_iterator_void);
    
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
    
    shared_ptr<basic_die> find_first_matching(
        bool(*pred)(shared_ptr<basic_die>, void *pred_arg), void *pred_arg);
    
	objects_iterator find_object_for_addr(unw_word_t addr);
    files_iterator find_file_for_addr(unw_word_t addr);

private:
	// typedefs for accessing the link map in the target process
    typedef unw_read_ptr<link_map> lm_ptr_t;
    typedef unw_read_ptr<char> remote_char_ptr_t;

    addr_t get_library_base_local(const string& path);
    addr_t get_library_base_remote(const string& path);
    addr_t get_library_base_from_maps(const string& path);
    bool rebuild_map();
    void update_rdbg();
    void update_i_executable();
    void update_executable_elf();
	/* void update_master_type_containment();
	void update_master_type_equivalence();
	
	virtual bool type_equivalence(shared_ptr<type_die> t1,
		shared_ptr<type_die> t2);
	
	void write_type_containment_relation(
		multimap<lib::Dwarf_Off, lib::Dwarf_Off>& out_mm,
		spec::abstract_dieset& ds); */
public:
	void 
	register_range_as_dieset(addr_t begin, addr_t end, 
    	shared_ptr<abstract_dieset> p_ds);

	addr_t 
	get_object_from_die(shared_ptr<with_static_location_die> d,
		lib::Dwarf_Addr vaddr);
		
    shared_ptr<basic_die> 
	discover_object_descr(addr_t addr,
    	shared_ptr<type_die> imprecise_static_type
         = shared_ptr<type_die>(),
        addr_t *out_object_start_addr = 0);

    shared_ptr<with_dynamic_location_die> 
	discover_stack_object(addr_t addr,
        addr_t *out_object_start_addr,
		addr_t *out_frame_base,
		addr_t *out_frame_return_addr
	);

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
		
public:
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

public:
    shared_ptr<with_static_location_die> 
	discover_object(
    	addr_t addr,
        addr_t *out_object_start_addr);
	
	std::ostream& print_object(std::ostream& s, void *obj) const;

#ifndef NO_DL_ITERATE_PHDR
    std::pair<GElf_Shdr, GElf_Phdr> get_static_memory_elf_headers(addr_t addr);
    // various ELF conveniences
    bool is_linker_code(addr_t addr)
    {	
    	auto kind = get_static_memory_elf_headers(addr);
    	return kind.first.sh_type == SHT_PROGBITS // FIXME: this is WRONG!
         && kind.second.p_type == PT_LOAD
         && (kind.second.p_flags & PF_X);
    }
#endif
    string nearest_preceding_symbol(addr_t addr); // FIXME: implement this

	struct symbols_iteration_state
	{
		Elf *elf;
		Elf_Scn *scn;
		GElf_Shdr shdr;
		Elf_Data *data;
		void *firstsym;
		void *lastsym;
		unsigned symcount;

		symbols_iteration_state(const process_image::files_iterator& i,
			Elf64_Word sh_type = SHT_DYNSYM);
		~symbols_iteration_state();
	};
	
	// NO! We can't do this, because it violates the portable usage of gelf.
	// We can't just increment a GElf_Sym* -- it will over-increment on 32-bit
	// platforms. 
	// typedef GElf_Sym *symbols_iterator_base;
	struct symbols_iterator_base 
	{ 
		unsigned pos; 
		bool operator==(const symbols_iterator_base& arg) const 
		{ return this->pos == arg.pos; }
	};
	
	struct symbols_iterator
	: public boost::iterator_adaptor<symbols_iterator,
		symbols_iterator_base,  // Base
		GElf_Sym, // Value
		boost::random_access_traversal_tag, // Traversal
		GElf_Sym, // Reference -- like value because we can't write through a GElf_Sym
		signed // Difference
	>
	{
		typedef symbols_iterator_base Base;
		
		typedef boost::iterator_adaptor<
			symbols_iterator, 
			symbols_iterator_base,
			GElf_Sym,
			boost::random_access_traversal_tag,
			GElf_Sym,
			signed
		> super;
		
		typedef symbols_iterator self;
		
		shared_ptr<symbols_iteration_state> origin;
		
		symbols_iterator(Base p, shared_ptr<symbols_iteration_state> origin)
		 : super(p), origin(origin) {}

		symbols_iterator() // no state
		 : super((symbols_iterator_base){ 0 }), origin() 
		 {
		 	cerr << "Warning: null symbol iterator constructed" << endl;
		 }
		
		//GElf_Sym& dereference() const
		GElf_Sym dereference() const
		{
			GElf_Sym sym;
			gelf_getsym(origin->data, base().pos, &sym);
			return sym;
		}
		
		void increment()
		{
			++base_reference().pos;
		}
		void decrement()
		{
			--base_reference().pos;
		}
		
		typedef signed difference_type;
		void advance(difference_type n)
		{
			base_reference().pos += n;
		}
		
		difference_type
		distance_to(
			self const& other
		)
		{
			return other.base_reference().pos - this->base_reference().pos;
		}

	};
	
	
	// NOTE: this makes a great example of lightweight data abstraction!
	// We want symbols_iterator to inherit the concepts of esym,
	// but we've added an extra field for destruction logic.
	// Maybe iterator_adapter is a more general case study
	pair<symbols_iterator, symbols_iterator> symbols(process_image::files_iterator& i,
		Elf64_Word sh_type = SHT_DYNSYM)
	{
		auto p_priv = boost::make_shared<symbols_iteration_state>(i, sh_type);
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

process_image::sym_binding_t resolve_symbol_from_process_image(
	const string& sym, void *p_pair);
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

std::ostream& operator<<(std::ostream& s, const process_image::memory_kind& k);

} // end namespace pmirror

#endif
