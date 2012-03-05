CFLAGS += -I../include
CFLAGS += -I$(MALLOC_HOOKS)
CFLAGS += -std=gnu99 -fPIC -g -O0 # need gnu99 for Linux-specific mmap() flags
CXXFLAGS += -I../include/pmirror
CXXFLAGS += -I../include
#CXXFLAGS += -std=c++0x -g
CXXFLAGS += -fPIC -fno-eliminate-unused-debug-types -fno-eliminate-unused-debug-symbols

LDFLAGS += -L../lib -Wl,-R$(realpath ../lib)

default: \
libpmirror.so \
libheap_index_hooks.so \
libheap_index_fast_hooks.so \
librtti.so \
libreflect.so

CPP_SRC := process.cpp stack.cpp heap.cpp static.cpp discover.cpp symbols.cpp map.cpp print.cpp
CPP_OBJS := $(patsubst %.cpp,%.o,$(CPP_SRC))
C_SRC := heap_index_hooks.c

CPP_DEPS := $(patsubst %.cpp,.%.d,$(CPP_SRC))
C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
DEPS := $(CC_DEPS) $(CPP_DEPS) $(C_DEPS)

$(CPP_DEPS): .%.d : %.cpp
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"
$(C_DEPS): .%.d : %.c
	$(CC) -MM $(CFLAGS) "$<"  > "$@"

-include $(DEPS)

ifeq ($(NO_LIBUNWIND),yes)
UNWIND_LDLIBS := 
else
UNWIND_LDLIBS += -lunwind-$$(uname -m) -lunwind-ptrace -lunwind 
endif

ifeq ($(LIBC_INCLUDES_LIBDL),yes)
LIBDL_LDLIBS :=
else
LIBDL_LDLIBS += -ldl
endif

librtti.so: librtti.cpp libreflect.so
	$(CXX) -shared -o "$@" $(CXXFLAGS) "$<" $(LDFLAGS) -lreflect 
libreflect.so: self-image.o
	$(CXX) -shared -o "$@" $(CXXFLAGS) "$<" $(LDFLAGS) #$(UNWIND_LDLIBS)

# First include the rules without the fancy CFLAGS.
# This builds a lean, mean set of hooks libraries.
libheap_index_hooks.so: heap_index_hooks.c $(MALLOC_HOOKS)/malloc_hooks.c 
	gcc $(LDFLAGS) -shared -o "$@" $(CFLAGS) "$<"

comma := ,
libheap_index_preload_hooks.so: heap_index_hooks.c $(wildcard $(MALLOC_HOOKS)/*.c)
	gcc $(LDFLAGS) -DMALLOC_HOOKS_INCLUDE="\"malloc_hooks_preload.c"\" \
	 -shared -g -fPIC -o "$@" $(CFLAGS) "$<" \
	$(patsubst %,-Wl$(comma)%,--defsym malloc=__wrap_malloc --defsym realloc=__wrap_realloc \
	--defsym calloc=__wrap_calloc --defsym free=__wrap_free \
	--defsym memalign=__wrap_memalign --defsym posix_memalign=__wrap_posix_memalign ) \
	$(MALLOC_HOOKS)/toplevel_init.c $(MALLOC_HOOKS)/linker_glue.c $(MALLOC_HOOKS)/early_malloc.c \
	

libheap_index_fast_hooks.so: heap_index_hooks.c $(MALLOC_HOOKS)/malloc_hooks.c 
	gcc $(LDFLAGS) -shared -o "$@" -DNDEBUG=1 -O3 -std=gnu99 -fPIC -g -I$(MALLOC_HOOKS) $(filter-out -O%,$(CFLAGS)) "$<"

# Now add the fancy CFLAGS for the libpmirror type-aware
# hooks.
#CFLAGS += -DHEAP_INDEX_TRAILER_INCLUDE=heap_index_type_field.inc
# NO! Don't do this. It's too fragile to have our library's ABI depend on CFLAGS. 
# Every client who includes heap_index.h will need to use the same flags. Work out
# a more robust approach. Maybe change the hooks so that they add a trailer and 
# *also* a user-defined amount of padding (to be defined by a separate structure)?
# But this has to be available early enough that the very first mallocs get it.
# UNLESS we store the padding size in the trailer! This sounds good.
libpmirror.so: $(CPP_OBJS) | libheap_index_fast_hooks.so #heap_index_hooks_with_type.o
	g++ $(LDFLAGS) -shared -o "$@" $+ -ldwarfpp -lboost_regex -lc++fileno -lelf -lsrk31c++ $(LIBDL_LDLIBS) -L. -Wl,-R$$(pwd) $(UNWIND_LDLIBS) 
#-lheap_index_fast_hooks #-ldwarf 

heap_index_hooks_with_type.o: heap_index_hooks.c $(MALLOC_HOOKS)/malloc_hooks.c 
	gcc $(CFLAGS) -c -o "$@" "$<"

clean:
	rm -f *.o *.so $(DEPS)
