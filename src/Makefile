MALLOC_HOOKS ?= $(HOME)/work/devel/malloc-hooks

CFLAGS += -I../include/processimage
CFLAGS += -I$(MALLOC_HOOKS)
CFLAGS += -std=gnu99 -fPIC -g -O0 # need gnu99 for Linux-specific mmap() flags
CXXFLAGS += -I../include/processimage
CXXFLAGS += -I${HOME}/scratch/opt/include
CXXFLAGS += -std=c++0x -fPIC -g -fno-eliminate-unused-debug-types -fno-eliminate-unused-debug-symbols

default: libprocessimage.so libheap_index_hooks.so libheap_index_fast_hooks.so

CPP_SRC := process.cpp
#C_SRC := malloc_hooks.c

CPP_DEPS := $(patsubst %.cpp,.%.d,$(CPP_SRC))
C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
DEPS := $(CC_DEPS) $(CPP_DEPS) $(C_DEPS)

$(CPP_DEPS): .%.d : %.cpp
	g++ -MM $(CXXFLAGS) "$<"  > "$@"
$(C_DEPS): .%.d : %.c
	gcc -MM $(CFLAGS) "$<"  > "$@"

include $(DEPS)

libprocessimage.so: process.o self-image.o libheap_index_fast_hooks.so
	g++ $(LDFLAGS) -shared -o "$@" $+ -ldwarfpp -lboost_regex -lc++fileno -lelf -lsrk31c++ -lunwind -lunwind-$$(uname -m) -lunwind-ptrace -ldl -L. -Wl,-R$$(pwd) -lheap_index_fast_hooks #-ldwarf 

libheap_index_hooks.so: heap_index_hooks.c $(MALLOC_HOOKS)/malloc_hooks.c 
	gcc $(LDFLAGS) -shared -o "$@" $(CFLAGS) "$<"

libheap_index_fast_hooks.so: heap_index_hooks.c $(MALLOC_HOOKS)/malloc_hooks.c 
	gcc $(LDFLAGS) -shared -pg -o "$@" -DNDEBUG=1 -O3 -std=gnu99 -fPIC -g -I$(MALLOC_HOOKS) $(CFLAGS) "$<"

clean:
	rm -f *.o *.so
