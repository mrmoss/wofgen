CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall
SRC=src

JSON_SRC=$(SRC)/json.cpp

all: wof

wof: $(SRC)/wof.cpp $(JSON_SRC)
	$(CXX) $(CFLAGS) $(SRC)/wof.cpp $(JSON_SRC) -o wof -Wno-tautological-constant-out-of-range-compare

clean:
	- rm -f wof wof.exe
