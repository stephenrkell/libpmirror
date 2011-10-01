#include <iostream>
#include <climits>
#include <cstdlib>
#include <processimage/process.hpp>

int main(int argc, char **argv)
{
	using namespace std;
	
	process_image self(-1);
	char *exec_realpath = realpath(argv[0], NULL);
	auto exec = self.files.find(exec_realpath);
	assert(exec != self.files.end());
	free(exec_realpath);
	auto syms = self.symbols(exec);
	cout << "Dynamic symbols in executable symtab: " << endl;
	for (auto i_sym = syms.first; i_sym != syms.second; i_sym++)
	{
		auto name = elf_strptr(i_sym.origin->elf, i_sym.origin->shdr.sh_link, 
			(size_t)i_sym->st_name);
		if(!name)
		{
			// null symbol name
			cout << "(null symbol name)" << endl;
		}
		else cout << name << endl;
	}
}
