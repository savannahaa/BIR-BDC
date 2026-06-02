CXX ?= g++
CXXFLAGS ?= -O3 -std=c++17 -Wall -Wextra -pedantic

TARGET := build/kkrt_pdc2_bench
SRC := src/kkrt_pdc2_bench.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	mkdir -p build
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -rf build
