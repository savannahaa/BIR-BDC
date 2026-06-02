CXX ?= c++
CXXFLAGS ?= -O3 -std=c++17 -Wall -Wextra -pedantic

BIN := mpsi_benchmark
SRC := src/mpsi_benchmark.cpp

.PHONY: all clean run-small

all: $(BIN)

$(BIN): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(BIN)

run-small: $(BIN)
	./$(BIN) -nu 5 -nn 12 -ts 100

clean:
	rm -f $(BIN)
