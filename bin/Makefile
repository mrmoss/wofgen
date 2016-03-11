CXX=g++
OPTS=-O
CFLAGS=$(OPTS) -Wall
SRC=../src

WOF_SRC=$(SRC)/main.cpp $(SRC)/parser.cpp

all: wof_ipfw wof_iptables wof_netsh wof_pf wof_ufw wof_wipfw

wof_ipfw: $(WOF_SRC) $(SRC)/ipfw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_IPFW

wof_iptables: $(WOF_SRC) $(SRC)/iptables.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_IPTABLES

wof_netsh: $(WOF_SRC) $(SRC)/netsh.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_NETSH

wof_pf: $(WOF_SRC) $(SRC)/pf.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_PF

wof_ufw: $(WOF_SRC) $(SRC)/ufw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_UFW

wof_wipfw: $(WOF_SRC) $(SRC)/wipfw.cpp
	$(CXX) $(CFLAGS) $^ -o $@ -D WOF_WIPFW

clean:
	- rm -f wof_ipfw wof_ipfw.exe
	- rm -f wof_iptables wof_iptables.exe
	- rm -f wof_netsh wof_netsh.exe
	- rm -f wof_pf wof_pf.exe
	- rm -f wof_ufw wof_ufw.exe
	- rm -f wof_wipfw wof_wipfw.exe
