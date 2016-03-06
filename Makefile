CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall
SRC=src
BIN=bin

all: wof_iptables wof_netsh wof_pf wof_ufw wof_ipfw

wof_iptables: $(SRC)/wof.cpp $(SRC)/iptables.cpp
	mkdir -p $(BIN)
	$(CXX) $(CFLAGS) $^ -o $(BIN)/$@

wof_netsh: $(SRC)/wof.cpp $(SRC)/netsh.cpp
	mkdir -p $(BIN)
	$(CXX) $(CFLAGS) $^ -o $(BIN)/$@

wof_pf: $(SRC)/wof.cpp $(SRC)/pf.cpp
	mkdir -p $(BIN)
	$(CXX) $(CFLAGS) $^ -o $(BIN)/$@

wof_ufw: $(SRC)/wof.cpp $(SRC)/ufw.cpp
	mkdir -p $(BIN)
	$(CXX) $(CFLAGS) $^ -o $(BIN)/$@

wof_ipfw: $(SRC)/wof.cpp $(SRC)/ipfw.cpp
	mkdir -p $(BIN)
	$(CXX) $(CFLAGS) $^ -o $(BIN)/$@

clean:
	- rm -f $(BIN)/wof_iptables $(BIN)/wof_iptables.exe
	- rm -f $(BIN)/wof_netsh $(BIN)/wof_netsh.exe
	- rm -f $(BIN)/wof_pf $(BIN)/wof_pf.exe
	- rm -f $(BIN)/wof_ufw $(BIN)/wof_ufw.exe
	- rm -f $(BIN)/wof_ipfw $(BIN)/wof_ipfw.exe
