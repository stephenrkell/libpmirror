#include "process.hpp"
#include <fstream>
#include <sstream>
#include <climits>
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

using dwarf::spec::basic_die;
using dwarf::spec::subprogram_die;
using dwarf::spec::type_die;
using dwarf::spec::variable_die;
using dwarf::spec::with_static_location_die;
using dwarf::spec::compile_unit_die;


void process_image::update()
{
	bool changed = rebuild_map();
	if (changed)
    {
    	update_i_executable();
	    update_executable_elf();
		/* update_master_type_equivalence();
		update_master_type_containment(); */
    }
}

bool process_image::rebuild_map()
{
    std::ostringstream filename;
    filename << "/proc/" << m_pid << "/maps";
    std::vector<std::string> map_contents;
    // read the maps file
    string line;
	std::ifstream map_file(filename.str());
    while (map_file)
    {
        std::getline(map_file, line, '\n'); 
        map_contents.push_back(line);
    }
    // has it changed since last update?
    if (map_contents == seen_map_lines) return false;
	// else... do the update
    seen_map_lines = map_contents;
	// open the process map for the file
    char seg_descr[PATH_MAX + 1];
	std::map<entry_key, entry> new_objects; // replacement map
    
    for (auto i = seen_map_lines.begin(); i != seen_map_lines.end(); i++)
    {
		#undef NUM_FIELDS
		#define NUM_FIELDS 11
        entry_key k;
        entry e;
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
            	    files[seg_descr].p_if = boost::make_shared<std::ifstream>(seg_descr);
                    if (*files[seg_descr].p_if)
                    {
	                    int fd = fileno(*files[seg_descr].p_if);
    	                if (fd != -1)
                        {
                    	    try
                            {
                    		    files[seg_descr].p_df = boost::make_shared<lib::file>(fd);
                                files[seg_descr].p_ds = boost::make_shared<lib::dieset>(
                        	        *files[seg_descr].p_df);
								/* write_type_containment_relation(
									files[seg_descr].ds_type_containment,
									*files[seg_descr].p_ds); */
                    	    }
                            catch (dwarf::lib::Error)
                            {
                        	    files[seg_descr].p_df = boost::shared_ptr<lib::file>();
                                files[seg_descr].p_ds = boost::shared_ptr<lib::dieset>();
                            }
                            catch (dwarf::lib::No_entry)
                            {
                        	    files[seg_descr].p_df = boost::shared_ptr<lib::file>();
                                files[seg_descr].p_ds = boost::shared_ptr<lib::dieset>();
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
        for (auto i = files.begin(); i != files.end(); i++)
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
}

void process_image::update_rdbg()
{
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
}

process_image::addr_t process_image::get_library_base_remote(const std::string& path)
{
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
process_image::find_file_by_realpath(const std::string& path)
{
	return std::find_if(this->files.begin(), this->files.end(), 
    	realpath_file_entry_cmp(path.c_str()));
}

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

} // end namespace pmirror
