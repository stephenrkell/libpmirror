include ../Makerules.common

default: \
libpmirror.a \
libpmirror.so \
librtti.so \
libreflect.so \
libheap_index_hooks.a \
libheap_index_hooks.so \
libheap_index_fast_hooks.a \
libheap_index_fast_hooks.so \
libheap_index_preload_hooks.so \
libheap_index_preload_fast_hooks.so \
libheap_index_wrap_hooks.a \
libreflect.a

# libheap_index_wrap_fast_hooks.a \

vpath %.c $(MALLOC_HOOKS)

CC_SRC := self-image.cc
CPP_SRC := process.cpp stack.cpp heap.cpp static.cpp discover.cpp symbols.cpp map.cpp print.cpp

CC_OBJS := self-image.o
CPP_OBJS := $(patsubst %.cpp,%.o,$(CPP_SRC))

C_SRC := heap_index_hooks.c addrmap.c

CC_DEPS := $(patsubst %.cc,.%.d,$(CC_SRC))
CPP_DEPS := $(patsubst %.cpp,.%.d,$(CPP_SRC))
C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))

DEPS := $(CC_DEPS) $(CPP_DEPS) $(C_DEPS)

$(CPP_DEPS): .%.d : %.cpp
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"
$(CC_DEPS): .%.d : %.cc
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"
$(C_DEPS): .%.d : %.c
	$(CC) -MM $(CFLAGS) "$<"  > "$@"

NON_FAST_CFLAGS += -DTRACE_DEEP_HEAP_INDEX # -DTRACE_MALLOC_HOOKS -DTRACE_HEAP_INDEX

-include $(DEPS)

ifeq ($(NO_LIBUNWIND),yes)
UNWIND_LDLIBS := 
else
UNWIND_LDLIBS += -lunwind-$(UNWIND_ARCH) -lunwind-ptrace -lunwind 
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
libreflect.a: self-image.o
	ar r "$@" $^

# FIXME: replace this with use of the Makerules in libmallochooks
comma := ,
libheap_index_preload_hooks.so: heap_index_hooks.c $(wildcard $(MALLOC_HOOKS)/*.c)
	gcc $(LDFLAGS) -DMALLOC_HOOKS_INCLUDE="\"malloc_hooks_preload.c"\" \
	 -shared -g -fpic -o "$@" $(CFLAGS) "$<" \
	$(patsubst %,-Wl$(comma)%,--defsym malloc=__wrap_malloc --defsym realloc=__wrap_realloc \
	--defsym calloc=__wrap_calloc --defsym free=__wrap_free \
	--defsym memalign=__wrap_memalign --defsym posix_memalign=__wrap_posix_memalign ) \
	$(MALLOC_HOOKS)/toplevel_init.c $(MALLOC_HOOKS)/dynamic_linker_glue.c \
	$(MALLOC_HOOKS)/common_linker_glue.c $(MALLOC_HOOKS)/early_malloc.c 
libheap_index_preload_fast_hooks.so: heap_index_hooks.c $(wildcard $(MALLOC_HOOKS)/*.c)
	gcc $(LDFLAGS) -DMALLOC_HOOKS_INCLUDE="\"malloc_hooks_preload.c"\" \
	 -shared -g -fpic -o "$@" $(COMMON_CFLAGS) -O4 -DNDEBUG=1 "$<" \
	$(patsubst %,-Wl$(comma)%,--defsym malloc=__wrap_malloc --defsym realloc=__wrap_realloc \
	--defsym calloc=__wrap_calloc --defsym free=__wrap_free \
	--defsym memalign=__wrap_memalign --defsym posix_memalign=__wrap_posix_memalign ) \
	$(MALLOC_HOOKS)/toplevel_init.c $(MALLOC_HOOKS)/dynamic_linker_glue.c \
	$(MALLOC_HOOKS)/common_linker_glue.c $(MALLOC_HOOKS)/early_malloc.c 
libheap_index_wrap_hooks.o: heap_index_hooks.c 
	gcc $(LDFLAGS) -DMALLOC_HOOKS_INCLUDE="\"malloc_hooks_wrap.c"\" \
	 -c -g -o $@ $(CFLAGS) $<
libheap_index_wrap_hooks.a: libheap_index_wrap_hooks.o toplevel_init.o static_linker_glue.o common_linker_glue.o
	ar r "$@" $^
	

# "old" hooks build rules
# First include the rules without the fancy CFLAGS.
# Then builds a lean, mean set of hooks libraries.
libheap_index_hooks.so: heap_index_hooks.c #$(MALLOC_HOOKS)/malloc_hooks.c 
	gcc $(LDFLAGS) -shared -o "$@" $(CFLAGS) $(NON_FAST_CFLAGS) "$<"
libheap_index_hooks.a: heap_index_hooks.c
	gcc $(LDFLAGS) -c $(CFLAGS) $(NON_FAST_CFLAGS) -I$(MALLOC_HOOKS) "$<"
	ar r "$@" heap_index_hooks.o #malloc_hooks.o

libheap_index_fast_hooks.so: heap_index_hooks.c #$(MALLOC_HOOKS)/malloc_hooks.c 
	gcc $(LDFLAGS) -shared -o "$@" -DNDEBUG=1 -O3 -std=gnu99 -fpic -g -I$(MALLOC_HOOKS) $(filter-out -O%,$(CFLAGS)) "$<"

#vpath $(MALLOC_HOOKS)/malloc_hooks.c 
libheap_index_fast_hooks.a: heap_index_hooks.c #malloc_hooks.c 
	gcc $(LDFLAGS) -c -DNDEBUG=1 -O3 -std=gnu99 -fpic -g -I$(MALLOC_HOOKS) $(filter-out -O%,$(CFLAGS)) $^
	ar r "$@" heap_index_hooks.o #malloc_hooks.o
	#rm -f malloc_hooks.o # HACK

# Now add the fancy CFLAGS for the libpmirror type-aware
# hooks.
#CFLAGS += -DHEAP_INDEX_TRAILER_INCLUDE=heap_index_type_field.inc
# NO! Don't do this. It's too fragile to have our library's ABI depend on CFLAGS. 
# Every client who includes heap_index.h will need to use the same flags. Work out
# a more robust approach. Maybe change the hooks so that they add a trailer and 
# *also* a user-defined amount of padding (to be defined by a separate structure)?
# But this has to be available early enough that the very first mallocs get it.
# UNLESS we store the padding size in the trailer! This sounds good.
libpmirror.so: $(CPP_OBJS) addrmap.o | libheap_index_fast_hooks.so 
	g++ $(LDFLAGS) -shared -o "$@" $+ -ldwarfpp -lboost_regex -lc++fileno -lelf -lsrk31c++ $(LIBDL_LDLIBS) -L. -Wl,-R$$(pwd) 
# $(UNWIND_LDLIBS) 
#-lheap_index_fast_hooks #-ldwarf 

libpmirror.a: $(CPP_OBJS) addrmap.o
	ar r "$@" $^

heap_index_hooks_with_type.o: heap_index_hooks.c $(MALLOC_HOOKS)/malloc_hooks.c 
	gcc $(CFLAGS) -c -o "$@" "$<"

clean:
	rm -f *.o *.so *.a $(DEPS)
