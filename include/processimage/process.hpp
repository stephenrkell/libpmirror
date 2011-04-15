#ifndef LIBCAKE_PROCESS_HPP
#define LIBCAKE_PROCESS_HPP

#include <string>
#include <map>
#include <set>
#include <functional>

#include <sys/types.h>

#include <link.h>

#include <boost/shared_ptr.hpp>
#include <boost/graph/graph_traits.hpp>

#include <gelf.h>

#include <dwarfpp/spec.hpp>
#include <dwarfpp/attr.hpp>
#include <dwarfpp/lib.hpp>
#include <dwarfpp/adt.hpp>

#include <libunwind.h>
#include <libunwind-ptrace.h>

#include <srk31/algorithm.hpp> // from libsrk31c++

extern "C" {
#include "objdiscover.h"
}

// DWARF x86 register numbers pilfered from libunwind/src/x86/unwind_i.h
#ifdef UNW_TARGET_X86
#define DWARF_X86_EAX     0
#define DWARF_X86_ECX     1
#define DWARF_X86_EDX     2
#define DWARF_X86_EBX     3
#define DWARF_X86_ESP     4
#define DWARF_X86_EBP     5
#define DWARF_X86_ESI     6
#define DWARF_X86_EDI     7
#define DWARF_X86_EIP     8
#define DWARF_X86_EFLAGS  9
#define DWARF_X86_TRAPNO  10
#define DWARF_X86_ST0     11
#endif
// similar for x86-64
#ifdef UNW_TARGET_X86_64
#define DWARF_X86_64_RAX     0
#define DWARF_X86_64_RDX     1
#define DWARF_X86_64_RCX     2
#define DWARF_X86_64_RBX     3
#define DWARF_X86_64_RSI     4
#define DWARF_X86_64_RDI     5
#define DWARF_X86_64_RBP     6
#define DWARF_X86_64_RSP     7
#define DWARF_X86_64_R8      8
#define DWARF_X86_64_R9      9
#define DWARF_X86_64_R10     10
#define DWARF_X86_64_R11     11
#define DWARF_X86_64_R12     12
#define DWARF_X86_64_R13     13
#define DWARF_X86_64_R14     14
#define DWARF_X86_64_R15     15
#define DWARF_X86_64_RIP     16
#endif

using namespace dwarf;
using boost::graph_traits;

/* This is a pointer-alike type which uses libunwind's memory accessors
 * rather than accessing memory directly. This allows access to a remote
 * process's address space as if it were local. Of course the remote 
 * process's ABI has to be compatible (wrt the type Target) with the local
 * process's ABI. Also, expressions involving multiple pointer hops (like
 * **foo or blah->bar->baz) won't work: you have to instantiate this class
 * around each intermediate pointer in turn. */
template <typename Target>
class unw_read_ptr
{

    unw_addr_space_t as;
    void *priv;
    Target *ptr;
    mutable Target buf;
public:
    typedef unw_read_ptr<Target> self_type;
    unw_read_ptr(unw_addr_space_t as, void *priv, Target *ptr) : as(as), priv(priv), ptr(ptr) {}
    Target operator*() const 
    { 
        Target tmp; 
        // simplifying assumption: either Target has a word-multiple size,
        // or is less than one word in size
        assert(sizeof (Target) < sizeof (unw_word_t)
        	|| sizeof (Target) % sizeof (unw_word_t) == 0); // simplifying assumption
        // tmp_base is just a pointer to tmp, cast to unw_word_t*
        unw_word_t *tmp_base = reinterpret_cast<unw_word_t*>(&tmp);
        
        // Handle the less-than-one-word case specially, for clarity
        if (sizeof (Target) < sizeof (unw_word_t))
        {
        	//std::cerr << "Read of size " << sizeof (Target) 
            //	<< " from unaligned address " << reinterpret_cast<void*>(ptr)
            //    << std::endl;
                
        	unw_word_t word_read;
            /* We can't trust access_mem not to access a whole word, 
             * so read the whole word and then copy it to tmp. */
            unw_word_t aligned_ptr 
            	= reinterpret_cast<unw_word_t>(ptr) & ~(sizeof (unw_word_t) - 1);
        	unw_get_accessors(as)->access_mem(as, 
	            aligned_ptr, // aligned read
                &word_read,
                0, // 0 means read, 1 means write
                priv);
            ptrdiff_t byte_offset = reinterpret_cast<char*>(ptr)
             - reinterpret_cast<char*>(aligned_ptr);
            //std::cerr << "Byte offset is " << byte_offset << std::endl;
            // now write to tmp directly
            tmp = *reinterpret_cast<Target*>(reinterpret_cast<char*>(&word_read) + byte_offset);
             
            return tmp;
        }
        else
        {
            // Now read memory one word at a time from the target address space
            for (unw_word_t *tmp_tgt = tmp_base;
        	    // termination condition: difference, in words,
                tmp_tgt - tmp_base < sizeof (Target) / sizeof (unw_word_t);
                tmp_tgt++)
            {
                off_t byte_offset // offset from ptr to the word we're currently reading
                 = reinterpret_cast<char*>(tmp_tgt) - reinterpret_cast<char*>(tmp_base);
                unw_get_accessors(as)->access_mem(as, 
                    reinterpret_cast<unw_word_t>(reinterpret_cast<char*>(ptr) + byte_offset), 
                    tmp_tgt,
                    0,
                    priv);
		    }            
            return tmp;
	    }	
    }
    // hmm... does this work? FIXME
    Target *operator->() const { this->buf = this->operator*(); return &this->buf; } 
    self_type& operator++() // prefix
    { ptr++; return *this; }
    self_type  operator++(int) // postfix ++
    { Target *tmp; ptr++; return self_type(as, priv, tmp); }
    self_type& operator--() // prefix
    { ptr++; return *this; }
    self_type  operator--(int) // postfix ++
    { Target *tmp; ptr--; return self_type(as, priv, tmp); }
    
    // we have two flavours of equality comparison: against ourselves,
    // and against unadorned pointers (risky, but useful for NULL testing)
    bool operator==(const self_type arg) { 
    	return this->as == arg.as
        && this->priv == arg.priv
        && this->ptr == arg.ptr; 
    }
    bool operator==(void *arg) { return this->ptr == arg; }
    
    bool operator!=(const self_type arg) { return !(*this == arg); }
    bool operator!=(void *arg) { return !(this->ptr == arg); }

	// default operator= and copy constructor work for us
    // but add another: construct from a raw ptr
    self_type& operator=(Target *ptr) { this->ptr = ptr; return *this; }
    self_type& operator+=(int arg) { this->ptr += arg; return *this; }
    self_type& operator-=(int arg) { this->ptr -= arg; return *this; }

    self_type operator+(int arg)
    { return self_type(as, priv, ptr + arg); }

    self_type operator-(int arg)
    { return self_type(as, priv, ptr - arg); }

    ptrdiff_t operator-(const self_type arg)
    { return this->ptr - arg.ptr; }
    
    operator void*() { return ptr; }
    
    /* Make this pointer-like thing also an iterator. */
    typedef std::random_access_iterator_tag iterator_category;
    typedef Target value_type;
    typedef ptrdiff_t difference_type;
    typedef Target *pointer;
    typedef Target& reference;
    

};

/* Register access implementation using libunwind. Instances may be 
 * passed to dwarf::lib::evaluator. */
class libunwind_regs : public dwarf::lib::regs
{
    unw_cursor_t *c;
public:
    dwarf::lib::Dwarf_Signed get(int i)
    {
        unw_word_t regval;
        switch(i)
        {
#ifdef UNW_TARGET_X86
            case DWARF_X86_EAX: unw_get_reg(c, UNW_X86_EAX, &regval); break;
			case DWARF_X86_EDX: unw_get_reg(c, UNW_X86_EDX, &regval); break;
			case DWARF_X86_ECX: unw_get_reg(c, UNW_X86_ECX, &regval); break;
			case DWARF_X86_EBX: unw_get_reg(c, UNW_X86_EBX, &regval); break;
			case DWARF_X86_ESI: unw_get_reg(c, UNW_X86_ESI, &regval); break;
            case DWARF_X86_EDI: unw_get_reg(c, UNW_X86_EDI, &regval); break;
            case DWARF_X86_EBP: unw_get_reg(c, UNW_X86_EBP, &regval); 
                std::cerr << "read EBP as 0x" << std::hex << regval << std::endl;
                break;
            case DWARF_X86_ESP: unw_get_reg(c, UNW_X86_ESP, &regval); 
                std::cerr << "read ESP as 0x" << std::hex << regval << std::endl;                    
                break;
            case DWARF_X86_EIP: unw_get_reg(c, UNW_X86_EIP, &regval); break;
            case DWARF_X86_EFLAGS: unw_get_reg(c, UNW_X86_EFLAGS, &regval); break;
            case DWARF_X86_TRAPNO: unw_get_reg(c, UNW_X86_TRAPNO, &regval); break;
#endif
#ifdef UNW_TARGET_X86_64
case DWARF_X86_64_RAX: unw_get_reg(c, UNW_X86_64_RAX, &regval); break;
case DWARF_X86_64_RDX: unw_get_reg(c, UNW_X86_64_RDX, &regval); break;
case DWARF_X86_64_RCX: unw_get_reg(c, UNW_X86_64_RCX, &regval); break;
case DWARF_X86_64_RBX: unw_get_reg(c, UNW_X86_64_RBX, &regval); break;
case DWARF_X86_64_RSI: unw_get_reg(c, UNW_X86_64_RSI, &regval); break;
case DWARF_X86_64_RDI: unw_get_reg(c, UNW_X86_64_RDI, &regval); break;
case DWARF_X86_64_RBP: unw_get_reg(c, UNW_X86_64_RBP, &regval); 
                std::cerr << "read RBP as 0x" << std::hex << regval << std::endl; break;
case DWARF_X86_64_RSP: unw_get_reg(c, UNW_X86_64_RSP, &regval); 
                std::cerr << "read RSP as 0x" << std::hex << regval << std::endl; break;
case DWARF_X86_64_R8: unw_get_reg(c, UNW_X86_64_R8, &regval); break;
case DWARF_X86_64_R9: unw_get_reg(c, UNW_X86_64_R9, &regval); break;
case DWARF_X86_64_R10: unw_get_reg(c, UNW_X86_64_R10, &regval); break;
case DWARF_X86_64_R11: unw_get_reg(c, UNW_X86_64_R11, &regval); break;
case DWARF_X86_64_R12: unw_get_reg(c, UNW_X86_64_R12, &regval); break;
case DWARF_X86_64_R13: unw_get_reg(c, UNW_X86_64_R13, &regval); break;
case DWARF_X86_64_R14: unw_get_reg(c, UNW_X86_64_R14, &regval); break;
case DWARF_X86_64_R15: unw_get_reg(c, UNW_X86_64_R15, &regval); break;
case DWARF_X86_64_RIP: unw_get_reg(c, UNW_X86_64_RIP, &regval); break;
#endif
            default:
                throw dwarf::lib::Not_supported("unsupported register number");
        }
        return regval;
    }
    libunwind_regs(unw_cursor_t *c) : c(c) {}
};
        
/* Utility function: search multiple diesets for the first 
 * DIE matching a predicate. */
boost::shared_ptr<dwarf::spec::basic_die> resolve_first(
    std::vector<std::string> path,
    std::vector<boost::shared_ptr<dwarf::spec::with_named_children_die> > starting_points,
    bool(*pred)(dwarf::spec::basic_die&) = 0);

struct process_image
{
	/* We maintain a map of loaded objects, so that we can maintain
     * a dieset open on each one. We must keep this map in sync with the
     * actual process map. */
    typedef unw_word_t addr_t;
	typedef std::pair<addr_t, addr_t> entry_key;
    
    static const char *ANONYMOUS_REGION_FILENAME;

    struct entry
    {
        char r, w, x, p;
        int offset;
        int maj, min;
        int inode;
        std::string seg_descr;
    };
    enum memory_kind
    {
	    UNKNOWN,
        STACK,
        HEAP,
        STATIC,
        ANON
    };
	static const char *name_for_memory_kind(/*memory_kind*/ int k); // relaxation for ltrace++
    
    struct file_entry
    {
		boost::shared_ptr<std::ifstream> p_if;
		boost::shared_ptr<dwarf::lib::file> p_df;
		boost::shared_ptr<dwarf::lib::abstract_dieset> p_ds;
		std::multimap<lib::Dwarf_Off, lib::Dwarf_Off> ds_type_containment;
    };
    
	std::map<entry_key, entry> objects;
    typedef std::map<entry_key, entry>::iterator objects_iterator;
    std::map<std::string, file_entry> files;
    typedef std::map<std::string, file_entry>::iterator files_iterator;
    
    /* For each registered file that is an [anon] segment, we record its
     * DWARF address separately. This is because addresses are process-relative
     * in DwarfPython diesets. */
    std::map<addr_t, addr_t> anon_segments_dwarf_bases;
    // FIXME: we currently ignore the .second of these pairs -- just using it
    // to track the known anonymous mappings
    
    /* Problem: all addresses could have i_file be the executable;
     * do we want to support i_file being libraries too? Do we want
     * a single vaddr to have multiple section_ and segment_addresses? */
    struct section_address
    { 
    	files_iterator i_file;
        std::string section_name;
        GElf_Off offset; // offset in file? or in vaddr-space defined by ELF file?
    };
    struct segment_address
    { 
    	files_iterator i_file;
        std::string segment_name;
        GElf_Off offset; // offset in file? or in vaddr-space defined by ELF file?
    };

private:
	pid_t m_pid;
	unw_addr_space_t unw_as;
	unw_accessors_t unw_accessors;
	void *unw_priv;
	unw_context_t unw_context;
	r_debug rdbg;
	std::vector<std::string> seen_map_lines;
	files_iterator i_executable; // points to the files entry representing the executable
	
	static const char *alloc_list_lib_basename;
	static const char *alloc_list_symname;
	addr_t alloc_list_head_ptr_addr; // base address of data structure holding heap metadata

	Elf *executable_elf;
	// equivalence classes of data types -- 
	// since according to our current definition, equivalent types always share
	// a list of idents below the CU level
	// (and we don't expect these to recur, although they theoretically could),
	// make this a map from these ident lists to sets of abstract_dieset::positions
	
public:
	typedef std::vector< boost::optional<std::string> > type_equivalence_class;
	typedef std::map<
		type_equivalence_class,
		std::set< dwarf::spec::abstract_dieset::position >
		> master_type_equivalence_t;
private:
	master_type_equivalence_t master_type_equivalence;
public:
	const master_type_equivalence_t& get_master_type_equivalence() const
	{ return master_type_equivalence; }
	master_type_equivalence_t& get_master_type_equivalence()
	{ return master_type_equivalence; }
	
	/* I thought about making master type containment  a *set of pairs*, 
	 * not a multimap (which is effectively a multiset of pairs). 
	 * This would mean we have to write our own find() and operator[],
	 * in effect, but don't have to be careful about checking
	 * for uniqueness of entries.
	 * Decided AGAINST this because uniqueness checking happens only on
	 * update(), i.e. a slow-path operation,
	 * whereas we want to be able to do a lookup for a given contained type *fast*. */
public:
	typedef std::/*set*/multimap< /*std::pair<*/type_equivalence_class, 
					type_equivalence_class/*>*/ >  master_type_containment_t;
	struct my_master_type_containment_t : public master_type_containment_t
	{
		process_image *containing_image;
		my_master_type_containment_t(process_image& i) 
		: master_type_containment_t(), containing_image(&i) {}
	};
private:
	my_master_type_containment_t master_type_containment;
public:
	const my_master_type_containment_t& get_master_type_containment() const
	{ return master_type_containment; }
	my_master_type_containment_t& get_master_type_containment()
	{ return master_type_containment; }
    process_image(pid_t pid = -1) 
    : m_pid(pid == -1 ? getpid() : pid),
      unw_as(pid == -1 ? 
      	unw_local_addr_space : 
        unw_create_addr_space(&_UPT_accessors/*&unw_accessors*/, 0)),
        executable_elf(0),
		master_type_containment(*this)
    {
    	int retval = unw_getcontext(&unw_context);
        assert(retval == 0);
    	if (pid == -1)
        {
        	unw_accessors = *unw_get_accessors(unw_local_addr_space);
            unw_priv = 0;
        }
        else 
        {
        	unw_accessors = _UPT_accessors;
        	unw_priv = _UPT_create(m_pid);
	    }
    	update();
    }
    void update();
    ~process_image() { if (executable_elf) elf_end(executable_elf); }
    
    std::map<std::string, file_entry>::iterator find_file_by_realpath(const std::string& path);
    memory_kind discover_object_memory_kind(addr_t addr);
    addr_t get_dieset_base(dwarf::lib::abstract_dieset& ds);
    addr_t get_library_base(const std::string& path);
    void register_anon_segment_description(addr_t base, 
        boost::shared_ptr<dwarf::lib::abstract_dieset> p_ds,
        addr_t base_for_dwarf_info);

	typedef dwarf::spec::with_runtime_location_die::sym_binding_t sym_binding_t;
    //sym_binding_t resolve_symbol(files_iterator file, const std::string& sym);
	//sym_binding_t resolve_symbol(
	//	const std::string& sym, void *p_file_iterator_void);
    
	typedef int (*stack_frame_cb_t)(process_image *image,
    	unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg);
    int walk_stack(void *stack_handle, stack_frame_cb_t handler, void *handler_arg);
    
    boost::shared_ptr<dwarf::spec::basic_die> find_first_matching(
        bool(*pred)(boost::shared_ptr<dwarf::spec::basic_die>, void *pred_arg), void *pred_arg);
    
	objects_iterator find_object_for_ip(unw_word_t ip);
    files_iterator find_file_for_ip(unw_word_t ip);
    boost::shared_ptr<dwarf::spec::compile_unit_die> find_compile_unit_for_ip(unw_word_t ip);    
    boost::shared_ptr<dwarf::spec::subprogram_die> find_subprogram_for_ip(unw_word_t ip);    
    boost::shared_ptr<dwarf::spec::with_runtime_location_die> find_most_specific_die_for_addr(addr_t addr);        

private:
	// typedefs for accessing the link map in the target process
    typedef unw_read_ptr<link_map> lm_ptr_t;
    typedef unw_read_ptr<char> remote_char_ptr_t;

    addr_t get_library_base_local(const std::string& path);
    addr_t get_library_base_remote(const std::string& path);
    bool rebuild_map();
    void update_rdbg();
    void update_i_executable();
    void update_executable_elf();
	void update_master_type_containment();
	void update_master_type_equivalence();
	
	virtual bool type_equivalence(boost::shared_ptr<dwarf::spec::type_die> t1,
		boost::shared_ptr<dwarf::spec::type_die> t2);
	
	void write_type_containment_relation(
		std::multimap<lib::Dwarf_Off, lib::Dwarf_Off>& out_mm,
		spec::abstract_dieset& ds);
public:
	void register_range_as_dieset(addr_t begin, addr_t end, 
    	boost::shared_ptr<dwarf::lib::abstract_dieset> p_ds);

	addr_t get_object_from_die(boost::shared_ptr<dwarf::spec::with_runtime_location_die> d,
		dwarf::lib::Dwarf_Addr vaddr);
    boost::shared_ptr<dwarf::spec::basic_die> discover_object_descr(addr_t addr,
    	boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type
         = boost::shared_ptr<dwarf::spec::type_die>(),
        addr_t *out_object_start_addr = 0);
    boost::shared_ptr<dwarf::spec::with_stack_location_die> discover_stack_object(addr_t addr,
        addr_t *out_object_start_addr);
    boost::shared_ptr<dwarf::spec::with_stack_location_die> discover_stack_object_local(
    	addr_t addr, addr_t *out_object_start_addr);
    boost::shared_ptr<dwarf::spec::with_stack_location_die> discover_stack_object_remote(
    	addr_t addr, addr_t *out_object_start_addr);
        
    boost::shared_ptr<dwarf::spec::basic_die> discover_heap_object(addr_t addr,
    	boost::shared_ptr<dwarf::spec::type_die> imprecise_static_type,
        addr_t *out_object_start_addr);
    boost::shared_ptr<dwarf::spec::with_runtime_location_die> discover_object(
    	addr_t addr,
        addr_t *out_object_start_addr);
    std::pair<GElf_Shdr, GElf_Phdr> get_static_memory_elf_headers(addr_t addr);
    // various ELF conveniences
    bool is_linker_code(addr_t addr)
    {	
    	auto kind = get_static_memory_elf_headers(addr);
    	return kind.first.sh_type == SHT_PROGBITS // FIXME: this is WRONG!
         && kind.second.p_type == PT_LOAD
         && (kind.second.p_flags & PF_X);
    }
    std::string nearest_preceding_symbol(addr_t addr); // FIXME: implement this
};

namespace boost {
template <>
struct graph_traits<process_image::my_master_type_containment_t>
{
	typedef process_image::type_equivalence_class vertex_descriptor;
	typedef process_image::my_master_type_containment_t::value_type edge_descriptor;

	// edge iterators are just iterators within the map
	typedef process_image::my_master_type_containment_t::iterator out_edge_iterator;

	/* vertex iterators are iterators through the set of 
	 * type equivalence classes in the map */
	typedef process_image::master_type_equivalence_t::iterator vertex_iterator;
	
	typedef process_image::master_type_equivalence_t::size_type vertices_size_type;
	typedef process_image::master_type_equivalence_t::size_type degree_size_type;

	// we are directed, and parallel edges are *not* allowed
	// (although one type may contain another in multiple locations...
	// ... but we capture this out-of-band)
	typedef directed_tag directed_category;
	typedef disallow_parallel_edge_tag edge_parallel_category;

	// we are both a vertex list graph and an incidence graph
    struct traversal_tag :
      public virtual vertex_list_graph_tag,
      public virtual incidence_graph_tag,
	  public virtual adjacency_graph_tag,
	  public virtual adjacency_matrix_tag { };
    typedef traversal_tag traversal_category;
	
	/* We are also an adjacency graph. This means that one can get an iterator
	 * for any vertex, that iterates through the vertices that can be reached
	 * from it in a single hop. We implement this just like out_edges. */
	typedef out_edge_iterator adjacency_iterator;
	
};

// template<> struct property_traits<process_image::my_master_type_containment_t>
// {
// 	/* vertex_property_type */
// 	typedef boost::no_property vertex_property_type;
// 
// };
} // end namespace boost

inline graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor
source(
    graph_traits<process_image::my_master_type_containment_t>::edge_descriptor e,
    const process_image::my_master_type_containment_t& g)
{
	return e.first;
}

inline graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor
target(
    graph_traits<process_image::my_master_type_containment_t>::edge_descriptor e,
    const process_image::my_master_type_containment_t& g)
{
	return e.second;
}

inline std::pair<
    graph_traits<process_image::my_master_type_containment_t>::out_edge_iterator,
    graph_traits<process_image::my_master_type_containment_t>::out_edge_iterator >  
out_edges(
    graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u, 
    const process_image::my_master_type_containment_t& g)
{
	return const_cast<process_image::my_master_type_containment_t&>(g).equal_range(u);
}

inline graph_traits<process_image::my_master_type_containment_t>::degree_size_type
out_degree(
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u,
	const process_image::my_master_type_containment_t& g)
{
	return srk31::count(
		const_cast<process_image::my_master_type_containment_t&>(g).equal_range(u).first, 
		const_cast<process_image::my_master_type_containment_t&>(g).equal_range(u).second);
}

inline std::pair<
    graph_traits<process_image::my_master_type_containment_t>::out_edge_iterator,
    graph_traits<process_image::my_master_type_containment_t>::out_edge_iterator >  
adjacent_vertices(graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u, 
    const process_image::my_master_type_containment_t& g)
{
	return const_cast<process_image::my_master_type_containment_t&>(g).equal_range(u);
}

inline std::pair<
	graph_traits<process_image::my_master_type_containment_t>::vertex_iterator,
	graph_traits<process_image::my_master_type_containment_t>::vertex_iterator >
vertices(const process_image::my_master_type_containment_t& g)
{
	// the tricky one: we need to get the associated equivalence map
	return std::make_pair(
		g.containing_image->get_master_type_equivalence().begin(),
		g.containing_image->get_master_type_equivalence().end());
}

inline graph_traits<process_image::my_master_type_containment_t>::vertices_size_type
num_vertices(const process_image::my_master_type_containment_t& g)
{
	return g.containing_image->get_master_type_equivalence().size();
}

inline graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor
add_vertex(process_image::my_master_type_containment_t& g)
{
	throw "blah";
}

inline void
remove_vertex(graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u,
	process_image::my_master_type_containment_t& g)
{
	g.containing_image->get_master_type_equivalence().erase(u);
}

inline std::pair<
	graph_traits<process_image::my_master_type_containment_t>::edge_descriptor, bool>
add_edge(
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u,
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor v, 
	process_image::my_master_type_containment_t& g)
{
	/* Insert -- we avoid inserting duplicates because
	 * it's a multimap and we want a multi-key unique-value map. */
	process_image::my_master_type_containment_t::value_type entry = std::make_pair(u, v);
	auto iter = std::find(
		g.begin(), 
		g.end(), 
		entry);
	if (iter == g.end())
	{
		g.insert(entry);
		return std::make_pair(entry, true);
	}
	else return std::make_pair(*iter, false);
}

/*

Semantics: Try to insert the edge (u,v) into the graph, returning the inserted edge or a parallel
edge and a flag that specifies whether an edge was inserted. This operation must not invalidate
vertex descriptors or vertex iterators of the graph, though it may invalidate edge descriptors or
edge iterators.

Preconditions: u and v are vertices in the graph. 

Postconditions: (u,v) is in the edge set of the graph. The returned edge descriptor will have u in
the source position and v in the target position. If the graph allows parallel edges, then the
returned flag is always true. If the graph does not allow parallel edges, if (u,v) was already in
the graph then the returned flag is false. If (u,v) was not in the graph then the returned flag is
true.

*/ 

inline void
remove_edge(
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u,
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor v, 
	process_image::my_master_type_containment_t& g)
{
	process_image::my_master_type_containment_t::value_type entry = std::make_pair(u, v);
	auto iter = std::find(
		g.begin(), 
		g.end(), 
		entry);
	if (iter == g.end()) return;
	else g.erase(iter);
}
/*

Semantics: Remove the edge (u,v) from the graph. If the graph allows parallel edges this removes
all occurrences of (u,v). 

Precondition: (u,v) is in the edge set of the graph. 

Postcondition: (u,v) is no longer in the edge set of the graph. 

*/

inline void 
remove_edge(
	graph_traits<process_image::my_master_type_containment_t>::edge_descriptor e,
	process_image::my_master_type_containment_t& g)
{
	auto iter = std::find(
		g.begin(), 
		g.end(), 
		e);
	if (iter != g.end()) g.erase(iter);
}

/*

Semantics: Remove the edge e from the graph.

Precondition: e is an edge in the graph. 

Postcondition: e is no longer in the edge set for g. 
*/

inline void 
clear_vertex(
	graph_traits<process_image::my_master_type_containment_t>::vertex_descriptor u, 
	process_image::my_master_type_containment_t& g)
{
	auto edges_pair = out_edges(u, g);
	for (auto i_edge = edges_pair.first; i_edge != edges_pair.second; i_edge++)
	{
		remove_edge(*i_edge, g);
	}
}	

/*

Semantics: Remove all edges to and from vertex u from the graph. 

Precondition: u is a valid vertex descriptor of g. 

Postconditions: u does not appear as a source or target of any edge in g.
*/
//} // end namespace boost

process_image::sym_binding_t resolve_symbol_from_process_image(
	const std::string& sym, /*process_image::files_iterator * */ void *p_file_iterator);
int stack_print_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg);
int stack_object_discovery_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg);
struct stack_object_discovery_handler_arg
{
	// in
	process_image::addr_t addr;
    // out
    boost::shared_ptr<dwarf::spec::with_stack_location_die> discovered_die;
    process_image::addr_t object_start_addr;
};        

std::ostream& operator<<(std::ostream& s, const process_image::memory_kind& k);

#endif
