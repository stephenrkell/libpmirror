include ../Makerules.common

CXXFLAGS += -g

LDLIBS  += -lpmirror
LDLIBS  += -ldwarfpp
LDLIBS  += -lc++fileno 
LDLIBS  += -lsrk31c++
LDLIBS  += -ldwarf 
LDLIBS  += -lelf -lsupc++ -lboost_regex
LDLIBS  += -lboost_serialization
LDLIBS  += -lunwind -lunwind-ptrace -lunwind-$(UNWIND_ARCH)
LDLIBS  += -ldl
LDLIBS  += -lrtti
LDLIBS  += -lreflect

SRC := $(wildcard *.cpp)
ALL_TESTS := $(patsubst %.cpp,%,$(SRC))

default: $(ALL_TESTS)

DEPS := $(patsubst %.cpp,.%.cpp.d,$(SRC))

$(DEPS): .%.cpp.d: %.cpp
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

include $(DEPS)

%: %.cpp 
	$(CXX) $(CXXFLAGS) -o "$@" "$<" $(LDFLAGS) $(LDLIBS)
