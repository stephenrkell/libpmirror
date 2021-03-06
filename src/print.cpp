#include "process.hpp"
#include <fstream>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <malloc.h>

extern "C" {
#include "heap_index.h"
}

#include <srk31/ordinal.hpp>

namespace pmirror {

using namespace dwarf;
/*using namespace dwarf::lib;*/ // omitted to remove Elf ambiguity
using std::string;
using std::ostream;
using std::cerr;
using std::pair;
using std::make_pair;

ostream& process_image::print_object(ostream& s, void *obj) const
{
	auto kind = discover_object_memory_kind((addr_t) obj);
	switch(kind)
	{
		case memory_kind::STACK:
			cerr << "stack object at " << obj; // FIXME
			return s;
		case memory_kind::HEAP:
		{
			void *obj_start;
			assert(index_region);
			struct insert *tr = lookup_object_info(obj, &obj_start, NULL, NULL);
			assert(tr);
			s << "pointer " << obj << " into object starting at " << obj_start
#ifndef NO_MALLOC_USABLE_SIZE
				<< " size " << malloc_usable_size(obj_start) 
#endif
				<< ", allocated at " << (void*)(uintptr_t)tr->alloc_site;
			return s;
		}
		case memory_kind::STATIC:
			cerr << "static object at " << obj; // FIXME:
			return s;
		
		case memory_kind::UNKNOWN:
		case memory_kind::ANON:
		default:
			cerr << "unknown object at " << obj; // FIXME
			return s;
	}
}

} // end namespace pmirror
