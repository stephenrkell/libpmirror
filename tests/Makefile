CXXFLAGS += -I../include
CXXFLAGS += -std=gnu++0x -g3 

CFLAGS += -I/usr/pkg/include
CFLAGS += -std=c99

LDFLAGS += -L../src -Wl,-R$(realpath ../src) 

LDLIBS  += -lpmirror
LDLIBS  += -ldwarfpp
LDLIBS  += -lc++fileno 
LDLIBS  += -lsrk31c++
LDLIBS  += -ldwarf 
LDLIBS  += -lelf -lsupc++ -lboost_regex
LDLIBS  += -lunwind -lunwind-ptrace -lunwind-$(shell arch)
LDLIBS  += -ldl
LDLIBS  += -lrtti
LDLIBS  += -lreflect

SRC := $(wildcard *.cpp)
ALL_TESTS := $(patsubst %.cpp,%,$(SRC))

default: $(ALL_TESTS)

DEPS := $(patsubst %.cpp,.%.cpp.d,$(SRC))

$(DEPS): .%.cpp.d: %.cpp
	g++ -MM $(CXXFLAGS) "$<"  > "$@"

include $(DEPS)


