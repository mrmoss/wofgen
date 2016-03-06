Walls of Fire - Universal firewall configuration generator.

Ever get tired of trying to remember how to use ipfw, iptables, netsh, pf, ufw, etc...?

Instead of trying to remember, learn the wof "simple syntax" and generate all of them:

Syntax:

	tcp/udp local_address/mask:local_port direction remote_address/mask:remote_port pass/deny

Current default option is deny (incoming and outgoing, need to add syntax to set this).

Enables established related on incoming ports (allow out what you allowed in).

Zero dependencies (other than a C++ compiler and the C++ STL).

Examples:

	#Enable DHCP Client (<> is both ways)
	udp any:68<>any:67 pass

	#Enable DNS Client to Google DNS
	udp any>8.8.8.8:53 pass

	#Enable WEB Client
	tcp any>any:80 pass
	tcp any>any:443 pass

	#Enable SSH Server
	tcp any<any:22 pass