#include <libreflect.hpp>
#include <cstdio>

int main(int argc, char **argv)
{
	pmirror::self.update();
	
	/* Now print the process map. */
	for (auto i_ent =  pmirror::self.objects.begin();
	          i_ent != pmirror::self.objects.end();
	          ++i_ent)
	{
		auto& k = i_ent->first;
		auto& e = i_ent->second;
		fprintf(stdout, 
			"%lx-%lx %c%c%c%c %8x %2x:%2x %d %s\n",
			k.first, k.second, e.r, e.w, e.x, e.p, e.offset, e.maj, e.min, e.inode, 
			e.seg_descr.c_str());
	}
	
	return 0;
}
