CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall
SRC=../src

WOFGEN_SRC=$(SRC)/main.cpp $(SRC)/parser.cpp $(SRC)/parser_util.cpp $(SRC)/string_util.cpp

all: wofgen_ipfw wofgen_iptables wofgen_netsh wofgen_pf wofgen_ipf wofgen_ufw wofgen_wipfw

wofgen_ipfw: $(WOFGEN_SRC) $(SRC)/ipfw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOFGEN_IPFW

wofgen_iptables: $(WOFGEN_SRC) $(SRC)/iptables.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOFGEN_IPTABLES

wofgen_netsh: $(WOFGEN_SRC) $(SRC)/netsh.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOFGEN_NETSH

wofgen_pf: $(WOFGEN_SRC) $(SRC)/pf.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOFGEN_PF

wofgen_ipf: $(WOFGEN_SRC) $(SRC)/ipf.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOFGEN_IPF

wofgen_ufw: $(WOFGEN_SRC) $(SRC)/ufw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOFGEN_UFW

wofgen_wipfw: $(WOFGEN_SRC) $(SRC)/wipfw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOFGEN_WIPFW

clean:
	- rm -f wofgen_ipfw wofgen_ipfw.exe
	- rm -f wofgen_iptables wofgen_iptables.exe
	- rm -f wofgen_netsh wofgen_netsh.exe
	- rm -f wofgen_pf wofgen_pf.exe
	- rm -f wofgen_ipf wofgen_ipf.exe
	- rm -f wofgen_ufw wofgen_ufw.exe
	- rm -f wofgen_wipfw wofgen_wipfw.exe
