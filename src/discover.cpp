#include "process.hpp"
#include <fstream>
#include <sstream>
#include <cstring>

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

/* Clearly one of these will delegate to the other. 
 * Which way round do they go? Clearly, discover_object_descr must first
 * delegate to discover_object, in case the object has its own variable DIE,
 * which might have a customised DWARF type. If that fails, we use the
 * generic object discovery stuff based on memory kind. */
 
/* Discover a DWARF type for an arbitrary object in the program address space. */
boost::shared_ptr<spec::basic_die> 
process_image::discover_object_descr(addr_t addr, 
	boost::shared_ptr<spec::type_die> imprecise_static_type /* = null ptr */,
	addr_t *out_object_start_addr /* = 0 */)
{
	switch(discover_object_memory_kind(addr))
	{
		case ANON:
		case STATIC: {
			auto discovered_obj = discover_object(addr, out_object_start_addr);
			if (discovered_obj)
			{
				if (discovered_obj->get_tag() == DW_TAG_variable)
					return dynamic_pointer_cast<
						dwarf::spec::variable_die>(discovered_obj)->get_type();
				else return discovered_obj; // HACK: return subprograms as their own descriptions
			}
			std::cerr << 
				"Warning: static object DIE search failed for static object at 0x" 
				<< addr << std::endl;
		} break;
		case STACK: {
			// DEBUG: dump the stack first
			walk_stack(NULL, stack_print_handler, 0);
			auto discovered_obj = discover_stack_object(addr, out_object_start_addr, 0, 0);
			if (discovered_obj && discovered_obj->get_type()) 
			{
				return discovered_obj->get_type();
			}
			else return boost::shared_ptr<spec::basic_die>();
		}
		case HEAP:
			return discover_heap_object(addr, imprecise_static_type, out_object_start_addr);
		default:
		case UNKNOWN:
			std::cerr << "Warning: unknown kind of memory at 0x" << std::hex << addr << std::dec << std::endl;
			return boost::shared_ptr<spec::basic_die>();
	}
}

const char *process_image::name_for_memory_kind(int k) // relaxation for ltrace++
{
	switch(k)
    {
        case STACK: return "stack";
        case STATIC: return "static";
        case HEAP: return "heap";
        case ANON: return "anon";
    	case UNKNOWN: 
        default: return "unknown";
	}    
}
std::ostream& operator<<(std::ostream& s, const process_image::memory_kind& k)
{
	s << process_image::name_for_memory_kind(k);
    return s;
}

process_image::memory_kind process_image::discover_object_memory_kind_from_maps(addr_t addr) const
{
	/* HACK: */ const_cast<process_image *>(this)->update();
	
	memory_kind ret = UNKNOWN;
	// for each range in the map...
	for (auto i_obj = objects.begin(); i_obj != objects.end(); ++i_obj)
    {
    	addr_t begin = i_obj->first.first;
        addr_t end = i_obj->first.second;
        // see whether addr matches this range
        if (addr >= begin && addr < end)
        {
        	const char *seg_descr = i_obj->second.seg_descr.c_str();
            // what sort of line is this?
            switch(seg_descr[0])
            {
                case '[':
                    if (strcmp(seg_descr, "[stack]") == 0)
                    {
                        ret = STACK; break;
				    }
                    else if (strcmp(seg_descr, "[heap]") == 0)
                    {
                        ret = HEAP; break;
                    }
                    else if (strcmp(seg_descr, "[anon]") == 0)
                    {
                case '\0': /* same treatment for nameless segments */
                        // hmm... if we *know* the anon segment, return it as 
                        // ANON; otherwise return it as heap
                        if (anon_segments_dwarf_bases.find(i_obj->first.first) 
                         != anon_segments_dwarf_bases.end())
                        {
                            ret = ANON; break;
                        }
                        else
                        {
                            ret = HEAP; break;
                        }
                    }
                    else 
                    {
                    	std::cerr << "Warning: did not understand segment description " 
                         << seg_descr
                         << " at address " << (void*)begin
                         << " in memory map of process " << m_pid
                         << std::endl;
                    	ret = UNKNOWN; break; 
                    }
                    //break;
                case '/': ret = STATIC; break;
                    //break;
                default: ret = UNKNOWN; break;
                    //break;
            }
        }
    }
	return ret;
}

} // end namespace pmirror
