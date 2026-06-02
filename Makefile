CXX ?= clang++
CXXFLAGS ?= -std=c++17 -O3 -Wall -Wextra -pedantic
CPPFLAGS ?= -Icpp/include

LIB_SRCS := cpp/src/crypto.cpp cpp/src/data.cpp cpp/src/okvs.cpp cpp/src/metrics.cpp cpp/src/protocol.cpp cpp/src/baselines.cpp
LDLIBS ?=

ifeq ($(USE_SHALLMATE_OKVS),1)
SHALLMATE_CPPFLAGS ?= -Ithird_party/OKVS
SHALLMATE_LDLIBS ?= -lcryptoTools -llibOTe
CPPFLAGS += -DBICDC_USE_SHALLMATE_OKVS $(SHALLMATE_CPPFLAGS)
LIB_SRCS += third_party/OKVS/SimpleIndex.cpp
LDLIBS += $(SHALLMATE_LDLIBS)
endif

.PHONY: all test clean

all: build/bicdc_cpp build/test_bicdc

build:
	mkdir -p build

build/bicdc_cpp: build $(LIB_SRCS) cpp/tools/run_bicdc.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LIB_SRCS) cpp/tools/run_bicdc.cpp -o $@ $(LDLIBS)

build/test_bicdc: build $(LIB_SRCS) cpp/tests/test_bicdc.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(LIB_SRCS) cpp/tests/test_bicdc.cpp -o $@ $(LDLIBS)

test: build/test_bicdc
	./build/test_bicdc

clean:
	rm -rf build
