default: lib

.PHONY: src
src:
	$(MAKE) -C src

.PHONY: clean
clean:
	$(MAKE) -C src clean
	rm -f lib/libprocessimage.so 


.PHONY: lib
lib: src
	test -L lib/libprocessimage.so || (mkdir -p lib && cd lib && ln -sf ../src/libprocessimage.so .)
