#include "process.hpp"
#include <fstream>
#include <sstream>
#include <climits>
#include <set>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cstring> /* for basename(), among other things -- must be the GNU version */
#include <fileno.hpp>
#include <malloc.h>


/* FIXME: currently we rely too much on manual updates of the memory map. 
 * We should really trap every event that changes the memory map
 * (dlopen(), mmap(), sbrk(), ...) 
 * and then dispense with the updates. */

#ifndef ELF_MAX_SEGMENTS
#define ELF_MAX_SEGMENTS 50
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN PATH_MAX
#endif

#ifdef HAVE_DLADDR
#include <dlfcn.h>
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
using std::map;
using std::set;
using std::vector;

using boost::dynamic_pointer_cast;
using boost::optional;
using boost::shared_ptr;
using boost::make_shared;

using dwarf::spec::basic_die;
using dwarf::spec::subprogram_die;
using dwarf::spec::type_die;
using dwarf::spec::variable_die;
using dwarf::spec::with_static_location_die;
using dwarf::spec::compile_unit_die;

intptr_t startup_brk;
static void save_startup_brk(void) __attribute__((constructor));
static void save_startup_brk(void)
{
	startup_brk = (intptr_t) sbrk(0);
}

void process_image::update()
{
	bool changed = rebuild_map();
	if (changed)
	{
		update_i_executable();
		update_executable_elf();
		update_intervals();
		/* update_master_type_equivalence();
		update_master_type_containment(); */
	}
}

bool process_image::rebuild_map()
{
	std::ostringstream filename;
	filename << "/proc/" << m_pid << "/maps";
	vector<string> map_contents;
	// read the maps file
	string line;
	std::ifstream map_file(filename.str());
#ifdef WORKAROUND_IFSTREAM_BUG
	std::istringstream in;
#else
	std::istream& in = map_file;
#endif
	if (map_file.rdstate() & std::ifstream::failbit)
	{
		throw string("Could not open maps file.");
	}
	
#ifdef WORKAROUND_IFSTREAM_BUG
	char all_data[100*1024]; // 100K should be enough
	//map_file.get(all_data, sizeof all_data, '\0'); // this has the same 1024-byte problem
	char *pos = &all_data[0];
	ssize_t ret = 0;
	while (pos += ret, (ret = read(fileno(map_file), pos, &all_data[sizeof all_data] - pos)) > 0);
	*pos = '\0';
	string all_data_string(all_data);
	in.str(all_data_string);
#endif
	
//	unsigned characters_read = 0;
//	bool fail_unchanged;
//	do
//	{
//		bool reset_failed = (map_file.fail() || map_file.eof()) ? (map_file.clear(), true) : false;
		while (std::getline(/*map_file*/ in, line, '\n'))
		{
//			characters_read += line.length() + (map_file ? 1 : 0); // +1 for newline
			map_contents.push_back(line);
		}
//		fail_unchanged = reset_failed && (map_file.fail() || map_file.eof());
//	} while (map_file || !fail_unchanged);
//	assert(map_file.eof());
	//assert(!map_file.bad());
	//assert(!map_file.fail());
	
	// has it changed since last update?
	if (map_contents == seen_map_lines) return false;
	// else... do the update
	seen_map_lines = map_contents;
	// open the process map for the file
	char seg_descr[PATH_MAX + 1];
	std::map<entry_key, entry> new_objects; // replacement map

	//cerr << "Saw " << seen_map_lines.size() << " lines (last: " << line << ")" << endl;
    for (auto i = seen_map_lines.begin(); i != seen_map_lines.end(); i++)
    {
		#undef NUM_FIELDS
		#define NUM_FIELDS 11
        entry_key k;
        entry e;
		cerr << "Line is: " << i->c_str() << endl;
        int fields_read = sscanf(i->c_str(), 
        	"%lx-%lx %c%c%c%c %8x %2x:%2x %d %s\n",
    	    &k.first, &k.second, &e.r, &e.w, &e.x, &e.p, &e.offset, &e.maj, &e.min, &e.inode, 
            seg_descr);

		// we should only get an empty line at the end
		if (fields_read == EOF) { assert(i+1 == seen_map_lines.end()); }
		else
		{
			if (fields_read < (NUM_FIELDS-1)) throw string("Bad maps data! ") + *i;

			if (fields_read == NUM_FIELDS) e.seg_descr = seg_descr;
			else e.seg_descr = std::string();

			if (objects.find(k) == objects.end() // common case: adding a new object
				|| string(objects.find(k)->second.seg_descr) != objects[k].seg_descr) 
				 // less common case: same start/end but different libname
			{
				if (seg_descr[0] == '/' && files.find(seg_descr) == files.end())
				{
					files[seg_descr].p_if = make_shared<std::ifstream>(seg_descr);
					if (*files[seg_descr].p_if)
					{
						int fd = fileno(*files[seg_descr].p_if);
						if (fd != -1)
						{
							try
							{
								files[seg_descr].p_df = make_shared<lib::file>(fd);
								files[seg_descr].p_ds = make_shared<lib::dieset>(
									*files[seg_descr].p_df);
								/* write_type_containment_relation(
									files[seg_descr].ds_type_containment,
									*files[seg_descr].p_ds); */
							}
							catch (dwarf::lib::Error)
							{
								files[seg_descr].p_df = shared_ptr<lib::file>();
								files[seg_descr].p_ds = shared_ptr<lib::dieset>();
							}
							catch (dwarf::lib::No_entry)
							{
								files[seg_descr].p_df = shared_ptr<lib::file>();
								files[seg_descr].p_ds = shared_ptr<lib::dieset>();
							}
						}
						else 
						{
							files[seg_descr].p_if->close();
						}
					}
				}
			}
			// now we can assign the new entry to the map
			new_objects[k] = e;
		}
	}
	objects = new_objects;
	return true;
}

void process_image::update_i_executable()
{
	/* FIXME: if a mapping goes away, we remove its entry but leave its 
	 * file open. This does no harm, but would be nice to delete it. */
	/* FIXME: we don't clear up anonymous mappings either, so if they get
	 * munmap()'ed and then something else mapped at the same address, we
	 * will get erroneous data. */
	/* We should have the executable open already -- find it. */
	std::ostringstream filename;
	filename << "/proc/" << m_pid << "/exe";
	//char link_target[PATH_MAX];
	//int retval;
	//retval = readlink(filename.str().c_str(), link_target, PATH_MAX);
	//assert(retval != -1);
	char real_exec[PATH_MAX];
	char *retpath;
	retpath = realpath(/*link_target*/filename.str().c_str(), real_exec);
	assert(retpath != NULL);
	i_executable = files.end();
	// HACK: we may have to go round twice, if we're racing
	// with a child about to exec(): we won't find the executable
	// first time, but assuming /proc/.../maps is replaced
	// atomically, we will find it second time.
	for (int j = 0; j < 2; j++)
	{
		for (auto i = files.begin(); i != files.end(); ++i)
		{
			if (i->first == std::string(real_exec))
			{
				/* Found the executable */
				i_executable = i;
				
				return;
			}
		}
		if (i_executable == files.end() && j == 0)
		{
			rebuild_map();
		}	
	}
	assert(false);
}

void process_image::update_executable_elf()
{
	assert(i_executable != files.end());
	int fd = fileno(*i_executable->second.p_if);
	assert(fd != -1);
	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		/* library out of date */
		/* recover from error */
		assert(0);
	}
	this->executable_elf = elf_begin(fd, ELF_C_READ, NULL);
	/* Record whether it's a dynamically linked executable. */
	bool is_dynamic = false;
	GElf_Ehdr ehdr;
	GElf_Ehdr *gelf_getehdr_ret = gelf_getehdr(executable_elf, &ehdr); 
	if (gelf_getehdr_ret != NULL) 
	{
		for (unsigned i_ph = 0; i_ph < ehdr.e_phnum; ++i_ph)
		{
			GElf_Phdr phdr;
			GElf_Phdr *gelf_getphdr_ret = gelf_getphdr(executable_elf, i_ph, &phdr);
			if (gelf_getphdr_ret != NULL) is_dynamic |= 
				(phdr.p_type == PT_DYNAMIC || phdr.p_type == PT_INTERP);
			if (is_dynamic) break;
		}
	}
	
	is_statically_linked = !is_dynamic;
}

void process_image::update_intervals()
{
	
	/* For each file we have loaded, reload its symbols. 
	 * FIXME: this is a bit brutal. Can we exploit some
	 * summary of the parts of the map that have changed? 
	 * We could thread two more parameters through from update_map():
	 * lines_deleted and lines_added. 
	 * Like in a diff, a change is just a delete and an add.*/
	intervals.clear();
	for (auto i_file = files.begin(); i_file != files.end(); ++i_file)
	{
		/*pair<
			concatenating_iterator<symbols_iterator>,
			concatenating_iterator<symbols_iterator>
		>*/ auto syms = //all_symbols(i_file);
			symbols(i_file, SHT_SYMTAB);
		
		map<addr_t, symbols_iterator> sorted_symbols;
		
		for (auto i_sym = syms.first; i_sym != syms.second; ++i_sym)
		{
			/* we only want defined nonnull syms */
			if ((i_sym->st_value == 0) ||
				(GELF_ST_BIND(i_sym->st_info)== STB_NUM) ||
				(
					(GELF_ST_TYPE(i_sym->st_info)!= STT_FUNC)
					&& (GELF_ST_TYPE(i_sym->st_info)!= STT_OBJECT)
					&& (GELF_ST_TYPE(i_sym->st_info)!= STT_COMMON) // FIXME: support TLS
				)) continue;
				
			addr_t sym_value = i_sym->st_value;
			
			cerr << "Calculated that symbol " 
				<< (i_sym./*base().*/get_symname() ? *i_sym./*base().*/get_symname() : "(no name)")
				<< " has address 0x" 
				<< std::hex << sym_value << std::dec
				<< endl;
			
			sorted_symbols.insert(make_pair(sym_value, i_sym/*.base()*/));
		}
		
		for (auto i_sym_pair = sorted_symbols.begin(); i_sym_pair != sorted_symbols.end();
			++i_sym_pair)
		{
			optional<decltype(i_sym_pair->second)> opt_next_sym;
			auto next_sym = i_sym_pair; ++next_sym;
			if (next_sym != sorted_symbols.end())
			{
				opt_next_sym = next_sym->second;
			}
			
			addr_t sym_value = i_sym_pair->first;
			optional<addr_t> opt_next_sym_value;
			if (opt_next_sym) { opt_next_sym_value = (*opt_next_sym)->st_value; }
			
			auto to_insert = make_pair(
				interval<addr_t>::right_open(
					sym_value, 
					opt_next_sym_value ? *opt_next_sym_value : sym_value
				), 
				interval_descriptor(i_sym_pair->second)
			);
			// cerr << "Inserting interval " << to_insert.first << endl;
			intervals.insert(to_insert);
		}
		
	}
	cerr << "Rebuilt interval tree of " << intervals.size() << " symbols." << endl;
}

process_image::addr_t process_image::get_dieset_base(dwarf::lib::abstract_dieset& ds)
{
    int retval;
    /* First get the filename of the dieset, by searching through
     * the files map. */
    files_iterator found = files.end();
    for (auto i = files.begin(); i != files.end(); i++)
    {
    	if (i->second.p_ds.get() == &ds) { found = i; break; }
    }
    if (found == files.end()) 
    {
		std::cerr << "Warning: failed to find library for some dieset..." << std::endl;
    	return 0; // give up
    }
    /* If it's the executable dieset or the dieset for an anonymous mapped 
     * region, the base address is zero. In the latter case, the search will
     * have found an anonymous region. */
    if (found == i_executable) return 0;
    if (found->first == ANONYMOUS_REGION_FILENAME)
    {
    	return 0; // success
    }

	return get_library_base(found->first.c_str());
}

const char *process_image::ANONYMOUS_REGION_FILENAME = /*"[anon]"*/ "";

#ifndef NO_DL_ITERATE_PHDR
struct callback_in_out
{
	const char *name_in;
    void *load_addr_out;
};
static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	const char *name_sought = ((callback_in_out *)data)->name_in;
    size_t sought_namelen = strlen(name_sought);
    size_t cur_obj_namelen = strlen(info->dlpi_name);
    // search for a *suffix match*
    // FIXME: fix s.t. prefix must end in '/'
	if (strncmp(info->dlpi_name + (cur_obj_namelen - sought_namelen),
    	name_sought, sought_namelen) == 0)
    {
    	((callback_in_out *)data)->load_addr_out = (void*) info->dlpi_addr;
    	return 1;
    }
    else return 0; // 0 means "carry on searching"
}
#endif
process_image::addr_t process_image::get_library_base(const std::string& path)
{
	char real_path[PATH_MAX]; 
    int retval;
    char *retpath = realpath(path.c_str(), real_path);
    assert(retpath != NULL);
    if (m_pid == getpid())
    {
    	/* use the local version */
        return get_library_base_local(std::string(real_path));
    }
    else
    {
    	/* use the remote version */
        return get_library_base_remote(std::string(real_path));
    }
}

process_image::addr_t process_image::get_library_base_local(const std::string& path)
{
#ifndef NO_DL_ITERATE_PHDR
    callback_in_out obj = { path.c_str()/*"libcake.so"*/, 0 };
    /* dl_iterate_phdr doesn't include the executable in its
     * list, so if we're looking for that, short-cut. */
    if (path == i_executable->first)
    {
    	return 0;
    }
    int retval = dl_iterate_phdr(phdr_callback, &obj);
    if (retval)
    {
    	// result -- we found the library
    	addr_t library_base = reinterpret_cast<addr_t>(obj.load_addr_out);
    	return library_base;
    }
    else
    {
		// not a result: didn't find the library
		std::cerr << "Warning: failed to find library for some DIE..." << std::endl;
		return 0;
	}
#else /* fall back on /proc version */
	return get_library_base_from_maps(path);
}

process_image::addr_t process_image::get_library_base_from_maps(const std::string& path)
{
	char arg_realpath[MAXPATHLEN];
	char *realpath_ret = realpath(path.c_str(), arg_realpath);
	assert(realpath_ret);

	set<addr_t> segment_base_addrs;
	auto found = std::find_if(
		objects.begin(),
		objects.end(), 
		[arg_realpath, &segment_base_addrs](const pair<entry_key, entry>& ent)
		{
			if (ent.second.seg_descr.length() > 0
				&& ent.second.seg_descr[0] == '/')
			{
				char ent_realpath[MAXPATHLEN];

				// it's a filename; is it our file?
				char *realpath_ret = realpath(ent.second.seg_descr.c_str(), ent_realpath);
				assert(realpath_ret);
				if (string(ent_realpath) == string(arg_realpath))
				{
					// is this an executable segment?
					//return ent.second.x == 'x';
					segment_base_addrs.insert(ent.first.first);
				} else return false;
			}
			else return false;
		}
	);

	if (segment_base_addrs.size() == 0)
	{
		std::cerr << "Warning: failed to find library for some DIE..." << std::endl;
		return 0;
	}
	else
	{
#if HAVE_DLADDR
		if (is_local)
		{
			/* This is the NetBSD case. */
			for (auto i_addr = segment_base_addrs.begin();
				i_addr != segment_base_addrs.end();
				++i_addr)
			{
				Dl_info info;
				int ret = dladdr((void*) *i_addr, &info);
				if (ret)
				{
					char fname_realpath_buf[PATH_MAX];
					char *fname_realpath = realpath(info.dli_fname, fname_realpath_buf);
					assert(fname_realpath);
					/* Is this file our file? */
					if (string(fname_realpath) == string(arg_realpath))
					{
						cerr << "Address " << (void*)*i_addr << " falls on or after some symbol in "
							<< info.dli_fname << " so selecting its load address "
							<< info.dli_fbase << " as the object's base." << endl;
						return (addr_t) info.dli_fbase;
					}
					else cerr << "Warning: address " << (void*)*i_addr 
						<< " beginning a segment of file " << arg_realpath
						<< " falls on or after some symbol in different file "
						<< info.dli_fname << endl;
					
				}
			}
			cerr << "No segment base address for " << arg_realpath
				<< " has a symbol preceding or equal to it within the same file." << endl;
		}
		// fall through
#endif
		// return the lowest element in the set.
		// FIXME: this is BROKEN!
		assert(false);
		return *segment_base_addrs.begin();
	}
#endif
}

void process_image::update_rdbg()
{
#ifndef NO_DL_ITERATE_PHDR
	void *dyn_addr = 0;
	GElf_Ehdr ehdr;
	if (this->executable_elf != NULL 
        && elf_kind(executable_elf) == ELF_K_ELF 
        && gelf_getehdr(executable_elf, &ehdr))
    {
	    for (int i = 1; i < ehdr.e_shnum; ++i) 
        {
		    Elf_Scn *scn;
		    GElf_Shdr shdr;
		    const char *name;

		    scn = elf_getscn(executable_elf, i);
		    if (scn != NULL && gelf_getshdr(scn, &shdr))
            {
			    name = elf_strptr(executable_elf, ehdr.e_shstrndx, shdr.sh_name);
                switch(shdr.sh_type)
                {
                    case SHT_DYNAMIC:
                    {
                    	dyn_addr = (void*)(unsigned long) shdr.sh_addr;
                        break;
                    }
                    default: continue;
                }
            }
        }
    }
    assert(dyn_addr != 0);
    /* Search the dynamic section for the DT_DEBUG tag. */
    int done = 0, i = 0;
	ElfW(Dyn) entry;
    
	unw_read_ptr<ElfW(Dyn)> search_ptr(
    	this->unw_as, this->unw_priv, 
        static_cast<ElfW(Dyn)*>(dyn_addr));
	
    void *dbg_addr;
    do
    {
     	entry = *search_ptr;
		if (entry.d_tag == DT_DEBUG) {
			done = 1;
			dbg_addr = reinterpret_cast<void*>(entry.d_un.d_val);
		}
        search_ptr++; // += sizeof (entry);
    } while (!done && entry.d_tag != DT_NULL && 
                ++i < ELF_MAX_SEGMENTS); // HACK: tolerate .dynamic sections not terminated by DT_NULL
    
    unw_read_ptr<r_debug> dbg_ptr(this->unw_as, this->unw_priv, 
    	static_cast<r_debug*>(dbg_addr));
    rdbg = *dbg_ptr;
	/* If we don't have a r_debug, this might segfault! */
    /*fprintf(stderr, "Found r_debug structure at %p\n", dbg_addr);*/
	
	/* Now we have rdbg, we can look for the heap metadata. Its base object
	 * lives in a well-known library at a well-known symbol name. */
	for (auto i_file = files.begin(); i_file != files.end(); ++i_file)
	{
		if (std::string(
				basename(
					const_cast<const char *>(i_file->first.c_str())
				)) == alloc_list_lib_basename)
		{
			//auto resolved = resolve_symbol(alloc_list_symname, &i_file);
			auto args = std::make_pair(
				this,
				i_file);
			
// 			auto resolved = resolve_symbol_from_process_image(alloc_list_symname, &args);
// 			if (resolved.file_relative_start_addr != 0 && resolved.size != 0)
// 			{
// 				/* success! */
// 				alloc_list_head_ptr_addr = 
// 				 get_library_base(i_file->first) + resolved.file_relative_start_addr;
// 				break;
// 			}
// FIXME: update this for memtable-based metadata
			assert(false);
		}
	}
#endif
}

process_image::addr_t process_image::get_library_base_remote(const std::string& path)
{
#ifndef NO_DL_ITERATE_PHDR
	update_rdbg();
    /* Now crawl the link map. */
    /* struct link_map rlm; */
	for(lm_ptr_t p_lm(this->unw_as, this->unw_priv, rdbg.r_map);
    	p_lm != 0; p_lm = p_lm->l_next)
    {
    	if (p_lm->l_name == NULL)
        {
			//fprintf(stderr, "Invalid library name referenced in dynamic linker map\n");
			return 0;
		}

		if (*remote_char_ptr_t(this->unw_as, this->unw_priv, p_lm->l_name) == '\0') {
			//fprintf(stderr, "Library name is an empty string\n");
			continue;
		}
        
        remote_char_ptr_t beginning_of_string(this->unw_as, this->unw_priv, p_lm->l_name);
        remote_char_ptr_t end_of_string(this->unw_as, this->unw_priv, p_lm->l_name);
        // advance remote pointer to end of string
        while (*++end_of_string != '\0');
        std::string name(beginning_of_string, end_of_string);

		//fprintf(stderr,
        //	"Library %s is loaded at 0x%x\n", name.c_str(), p_lm->l_addr);
        if (path == name) return p_lm->l_addr;
	}
    return 0;
#else
	return get_library_base_from_maps(path);
#endif
}
    
void process_image::register_anon_segment_description(addr_t base, 
        boost::shared_ptr<dwarf::lib::abstract_dieset> p_ds,
        addr_t base_for_dwarf_info)
{
	assert(p_ds);
    this->update();
	// update any existing mapping
    anon_segments_dwarf_bases[base] = base_for_dwarf_info;
    // create file record if none exists
    if (files.find(ANONYMOUS_REGION_FILENAME) == files.end())
    {
        // FIXME: supports only one anonymous region, for now
        files.insert(std::make_pair(
            std::string(ANONYMOUS_REGION_FILENAME),
            (file_entry) { boost::shared_ptr<std::ifstream>(),
                            boost::shared_ptr<dwarf::lib::file>(),
                            p_ds }
        ));
    }
    else
    {
    	// we should not have added more than one file named [anon]
        assert(files[std::string(ANONYMOUS_REGION_FILENAME)].p_ds == p_ds);
    }
}

struct realpath_file_entry_cmp 
: public std::unary_function<std::pair<std::string, process_image::file_entry>, bool>
{
	char path_real[PATH_MAX];
	realpath_file_entry_cmp(const char *path) 
    { char *retval = realpath(path, path_real); assert(retval != NULL); }
	bool operator()(const std::pair<std::string, process_image::file_entry>& arg) const
    {
    	char arg_real[PATH_MAX];
        realpath(arg.first.c_str(), arg_real);
        return strcmp(arg_real, path_real) == 0;
    }
};
std::map<std::string, process_image::file_entry>::iterator 
process_image::find_file_by_realpath(
	const std::string& path, 
	optional< map<string, process_image::file_entry>::iterator> begin_here
)
{
	return std::find_if(begin_here ? *begin_here : this->files.begin(), this->files.end(), 
    	realpath_file_entry_cmp(path.c_str()));
}

#ifndef NO_DL_ITERATE_PHDR
std::pair<GElf_Shdr, GElf_Phdr> process_image::get_static_memory_elf_headers(addr_t addr)
{
	assert(this->executable_elf != NULL 
        && elf_kind(executable_elf) == ELF_K_ELF);
	std::pair<GElf_Shdr, GElf_Phdr> retval; //= std::make_pair(SHT_NULL, PT_NULL);
    retval.first.sh_type = SHT_NULL;
    retval.second.p_type = PT_NULL;
            
    GElf_Ehdr ehdr;
    if (gelf_getehdr(executable_elf, &ehdr))
    {
	    for (int i = 1; i < ehdr.e_shnum; ++i) 
        {
		    Elf_Scn *scn;
		    GElf_Shdr shdr;

		    scn = elf_getscn(executable_elf, i);
		    if (scn != NULL && gelf_getshdr(scn, &shdr))
            {
                addr_t section_begin_addr = shdr.sh_addr;
                addr_t section_end_addr = shdr.sh_addr + shdr.sh_size;
                if (addr >= section_begin_addr && addr < section_end_addr)
                {
                    /* Found it! */
                    retval.first = shdr/*.sh_type*/;
                }
            }
        }
    } 
    else assert(false); // we assume gelf_getehdr won't fail

	GElf_Phdr phdr;
    if (gelf_getphdr(executable_elf, 0, &phdr))
    {
        // we got the first phdr
        assert(phdr.p_type == PT_PHDR);
        unsigned num_entries = phdr.p_memsz / sizeof (ElfW(Phdr));
        for (int i = 1; i < num_entries; i++)
        {
        	GElf_Phdr *success = gelf_getphdr(executable_elf, i, &phdr);
            if (success)
            {
				addr_t segment_begin_vaddr = phdr.p_vaddr;
                addr_t segment_end_vaddr = segment_begin_vaddr + phdr.p_memsz;
            	if (addr >= segment_begin_vaddr && addr < segment_end_vaddr)
                {
                	retval.second = phdr/*.p_type*/;
                }
			}
            else
            {
            	fprintf(stderr, "Error getting program header at index %d.\n", i);
            }
        }
    }

    // every static addr should be accounted for by shdrs
    if (retval.first.sh_type != SHT_NULL && retval.second.p_type != PT_NULL) return retval; 
    assert(this->discover_object_memory_kind(addr) != STATIC);
    // call didn't respect precondition
    assert(false);
}
#endif

} // end namespace pmirror
