#include <cstdio>
#include <cstdlib>
extern "C" {
#include "objdiscover.h"
}
#include <sstream>
#include <map>
#include <process.hpp>

int ready;

void *get_self_image(void)
{
	static process_image self(-1);
	
	return &self;
}

void print_guessed_region_type(void *img, void *begin, size_t size, const void *caller)
{
	static std::multimap<const void *, size_t> printed;
	auto seen_before = printed.equal_range(caller); 
	for (auto i_seen = seen_before.first; i_seen != seen_before.second; i_seen++)
	{	if (i_seen->first == caller && i_seen->second == size)
		{   // already seen this alloc site and size
			return;
		}
	}
	printed.insert(std::make_pair(caller, size));
	
	process_image *image = reinterpret_cast<process_image*>(img);
	
	/* Look up types defined in the caller. */
	boost::shared_ptr<dwarf::spec::compile_unit_die> p_cu =
		image->find_compile_unit_for_ip(reinterpret_cast<unw_word_t>(caller)); 
	
	if (!p_cu)
	{
		fprintf(stderr, "Not guessing a type for allocation site %p -- no debug info.\n", caller);
		return;
	}
	fprintf(stderr, "malloc() from %p, size %d...\n", caller, size);
	/* First just collapse all the byte- and word-sized types into a single message. */
	fprintf(stderr, "... might be block of %d instance(s) of a bytesize type.\n", size);
	if (size % sizeof(int) == 0) 
	{
		fprintf(stderr, "... might be block of %d instance(s) of a wordsize type.\n", size/sizeof(int));
	}
	
	/* For each descendent that is a data type... */
	unsigned cu_depth = p_cu->iterator_here().base().path_from_root.size();
	for (auto iter = ++p_cu->iterator_here(); 
		iter.base().path_from_root.size() > cu_depth;
		iter++)
	{
		auto p_type = boost::dynamic_pointer_cast<dwarf::spec::type_die>(*iter);
		if (p_type && p_type->get_concrete_type()
			&& p_type->get_tag() != DW_TAG_array_type // we handle arrays specially
			&& p_type->get_concrete_type()->iterator_here() == p_type->iterator_here())
		{
			//fprintf(stderr, "Considering a type.\n");
			auto opt_byte_size = p_type->calculate_byte_size();
			if (opt_byte_size && *opt_byte_size != sizeof (int) && *opt_byte_size != 1)
			{
				int rem = size % *opt_byte_size;
				int quot = size / *opt_byte_size;
				if (rem == 0)
				{
					std::ostringstream buf;
					buf << "... might be block of " 
						<< quot
						<< " instance(s) of " 
						<< p_type->get_spec().tag_lookup(p_type->get_tag()) 
						<< " type " 
						<< (p_type->get_name() ? *p_type->get_name() : "(anonymous)")
						<< " at 0x" << std::hex << p_type->get_offset();
						
					fprintf(stderr, "%s\n", buf.str().c_str());
				}
			}
			
		}
	}
}	
