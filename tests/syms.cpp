#include <iostream>
#include <climits>
#include <cstdlib>
#include <pmirror/process.hpp>
#include <srk31/algorithm.hpp>

using pmirror::process_image;

#ifndef PATH_MAX
#define PATH_MAX MAXPATHLEN 
#endif

int main(int argc, char **argv)
{
	using namespace std;
	
	process_image self(-1);
	self.update();
	char exec_realpathbuf[PATH_MAX];
	char *exec_realpath = realpath(argv[0], exec_realpathbuf);
	auto exec = self.files.find(exec_realpath);
	assert(exec != self.files.end());
	auto syms = self.symbols(exec);
	cout << "Dynamic symbols in executable symtab: " << endl;
	for (auto i_sym = syms.first; i_sym != syms.second; i_sym++)
	{
		auto name = elf_strptr(i_sym.origin->elf, i_sym.origin->shdr.sh_link, 
			(size_t)i_sym->st_name);
		if(!name)
		{
			// null symbol name
			//cout << "(null symbol name)" << endl;
		}
		else {} //cout << name << endl;
	}
	auto static_symbols = self.static_symbols(exec);
	auto dynamic_symbols = self.dynamic_symbols(exec);
	auto all_symbols = self.all_symbols(exec);
	unsigned static_symbols_count = srk31::count(
		static_symbols.first, static_symbols.second
	);
	unsigned dynamic_symbols_count = srk31::count(
		dynamic_symbols.first, dynamic_symbols.second
	);
	unsigned all_symbols_count = srk31::count(
		all_symbols.first, all_symbols.second
	);
	assert(all_symbols_count
	 == static_symbols_count + dynamic_symbols_count);

	return 0;
}
