CXX=g++
OPTS=-O
LIBS=
CFLAGS=$(OPTS) -Wall
SRC=src

JSON_SRC=$(SRC)/json.cpp

ifeq ($(OS),Windows_NT)
	LIBS+=-lWs2_32
endif

all: wof

wof: $(SRC)/wof.cpp $(JSON_SRC)
	$(CXX) $(CFLAGS) $(SRC)/wof.cpp $(JSON_SRC) $(LIBS) -o wof -Wno-tautological-constant-out-of-range-compare

clean:
	- rm -f wof wof.exe
