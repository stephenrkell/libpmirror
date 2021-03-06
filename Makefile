default: lib

.PHONY: src
src:
	$(MAKE) -C src

.PHONY: clean
clean:
	$(MAKE) -C src clean
	rm -f lib/*.so 
	rm -f lib/*.a


.PHONY: lib
lib: src
	test -L lib/libpmirror.so || (mkdir -p lib && cd lib && ln -sf ../src/libpmirror.so .)
	test -L lib/libpmirror.a || (mkdir -p lib && cd lib && ln -sf ../src/libpmirror.a .)
	test -L lib/librtti.so || (mkdir -p lib && cd lib && ln -sf ../src/librtti.so .)
	test -L lib/libreflect.so || (mkdir -p lib && cd lib && ln -sf ../src/libreflect.so .)
	test -L lib/libreflect.a || (mkdir -p lib && cd lib && ln -sf ../src/libreflect.a .)
	test -L lib/libheap_index_hooks.so || (mkdir -p lib && cd lib && ln -sf ../src/libheap_index_hooks.so .)
	test -L lib/libheap_index_hooks.a || (mkdir -p lib && cd lib && ln -sf ../src/libheap_index_hooks.a .)
	test -L lib/libheap_index_fast_hooks.so || (mkdir -p lib && cd lib && ln -sf ../src/libheap_index_fast_hooks.so .)
	test -L lib/libheap_index_fast_hooks.a || (mkdir -p lib && cd lib && ln -sf ../src/libheap_index_fast_hooks.a .)
	test -L lib/libheap_index_preload_hooks.so || (mkdir -p lib && cd lib && ln -sf ../src/libheap_index_preload_hooks.so .)
	test -L lib/libheap_index_preload_fast_hooks.so || (mkdir -p lib && cd lib && ln -sf ../src/libheap_index_preload_fast_hooks.so .)
