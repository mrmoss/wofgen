Walls of Fire - Universal firewall configuration generator.

Ever get tired of trying to remember how to use ipfw, iptables, netsh, ipf/pf, ufw, wipfw, etc...?

Instead of trying to remember, learn the wof "simple syntax" and generate all of them:

	Syntax:
		tcp/udp local_address/mask:local_port direction remote_address/mask:remote_port pass/deny

Enables established related on incoming ports (allow out what you allowed in).

Zero dependencies (other than a C++ compiler and the C++ STL).

Eveything but ipf/pf and wipfw cranks out commands that can be run in a terminal.

Sadly, ipf/pf and wipfw require the use of a configuration file, so that is generated instead.

Example Configuration Lines:

	#DHCP Client (<> is both ways)
	udp any:68<>any:67 pass

	#DNS Client to Google DNS
	udp any>8.8.8.8:53 pass

	#WEB Client
	tcp any>any:80 pass
	tcp any>any:443 pass

	#SSH Server
	tcp any<any:22 pass

Example Usage:

	#Universal
	bin/wofgen_iptables rules.wof

	#Unix/Cygwin
	cat rules.wof|bin/wofgen_ipfw

	#Windows
	type rules.wof|bin\wofgen_netsh

Web Version:

There is a running version at: https://nullify.cc/wof/
