CFLAGS += -I../include/processimage
CFLAGS += -std=c99 -fPIC -g
CXXFLAGS += -I../include/processimage
CXXFLAGS += -I${HOME}/scratch/opt/include
CXXFLAGS += -std=c++0x -fPIC -g -fno-eliminate-unused-debug-types -fno-eliminate-unused-debug-symbols

default: libprocessimage.so

CPP_SRC := process.cpp
C_SRC := malloc_hooks.c

CPP_DEPS := $(patsubst %.cpp,.%.d,$(CPP_SRC))
C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
DEPS := $(CC_DEPS) $(CPP_DEPS) $(C_DEPS)

$(CPP_DEPS): .%.d : %.cpp
	g++ -MM $(CXXFLAGS) "$<"  > "$@"
$(C_DEPS): .%.d : %.c
	gcc -MM $(CFLAGS) "$<"  > "$@"

include $(DEPS)

libprocessimage.so: process.o malloc_hooks.o self-image.o
	g++ $(LDFLAGS) -shared -o "$@" $+ -ldwarfpp -Wl,--whole-archive -ldwarf -Wl,--no-whole-archive -lboost_regex -lc++fileno -lelf -lsrk31c++ -lunwind -lunwind-x86 -lunwind-ptrace

clean:
	rm -f *.o *.so
