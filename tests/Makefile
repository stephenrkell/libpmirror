COMMON_CFLAGS += -I$(SRCROOT)/include
COMMON_CFLAGS += -I$(MALLOC_HOOKS)
COMMON_CFLAGS += -std=gnu99 -fpic -g
CFLAGS += -std=gnu99 -fpic -g #-O0 

CXXFLAGS += -I../include/pmirror
CXXFLAGS += -I../include
CXXFLAGS += -std=c++0x
CXXFLAGS += -fPIC -fno-eliminate-unused-debug-types -fno-eliminate-unused-debug-symbols

LDFLAGS += -L$(SRCROOT)/src -Wl,-R$(SRCROOT)/src -L$(SRCROOT)/lib -Wl,-R$(SRCROOT)/lib

# get the architecture, with override for this stupid i386/i686 confusion
CXXFLAGS += -g

SRC := $(wildcard *.cpp)
ALL_TESTS := $(patsubst %.cpp,%,$(SRC))

default: $(ALL_TESTS)

DEPS := $(patsubst %.cpp,.%.cpp.d,$(SRC))

$(DEPS): .%.cpp.d: %.cpp
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

include $(DEPS)

%: %.cpp 
	$(CXX) $(CXXFLAGS) -o "$@" "$<" $(LDFLAGS) $(LDLIBS)
