#ifndef PMIRROR_SYMBOLS_HPP_
#define PMIRROR_SYMBOLS_HPP_

#include <string>
#include <map>
#include <set>
#include <iostream>

#include <memory>
#include <boost/optional.hpp>
#include <boost/iterator_adaptors.hpp>
#include <gelf.h>

namespace pmirror
{
	using std::shared_ptr;
	using boost::dynamic_pointer_cast;
	using boost::optional;
	using std::vector;
	using std::string;
	using std::pair;
	using std::make_pair;
	using std::map;
	using std::multimap;
	using std::cerr;
	using std::endl;

	struct symbols_iteration_state
	{
		Elf *elf;
		Elf_Scn *scn;
		GElf_Shdr shdr;
		Elf_Data *data;
		void *firstsym;
		void *lastsym;
		unsigned symcount;

		symbols_iteration_state(Elf *e,
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
		symbols_iterator_base() : pos(0U) {}
		symbols_iterator_base(unsigned pos) : pos(pos) {}
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
		 : super(0), origin() 
		{
			//cerr << "Warning: null symbol iterator constructed" << endl;
			//assert(false);
		}
		
		//GElf_Sym& dereference() const
		GElf_Sym dereference() const
		{
			GElf_Sym sym;
			assert(origin->firstsym);
			assert(origin->lastsym);
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
		
		const char *
		get_strptr() const
		{
			assert(origin->firstsym);
			assert(origin->lastsym);
			assert(base().pos < origin->symcount);
			auto strptr = elf_strptr(origin->elf,
				origin->shdr.sh_link, 
				dereference().st_name);
			return strptr;
		}
		
		optional<string>
		get_symname() const
		{
			auto strptr = get_strptr();
			if (strptr) return string(strptr);
			else return optional<string>();
		}
	};
}

#endif
