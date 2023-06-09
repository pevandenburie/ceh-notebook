CEH Notebook
============

Sniffing
--------

## Perform Active Sniffing

MAC Flooding: Involves flooding the CAM table with fake MAC address and IP pairs until it is full

DNS Poisoning: Involves tricking a DNS server into believing that it has received authentic information when, in reality, it has not

ARP Poisoning: Involves constructing a large number of forged ARP request and reply packets to overload a switch

DHCP Attacks: Involves performing a DHCP starvation attack and a rogue DHCP server attack

Switch port stealing: Involves flooding the switch with forged gratuitous ARP packets with the target MAC address as the source

Spoofing Attack: Involves performing MAC spoofing, VLAN hopping, and STP attacks to steal sensitive information


### Perform MAC flooding using macof

macof is a Unix and Linux tool that is a part of the dsniff collection. It floods the local network with random MAC addresses and IP addresses, causing some switches to fail and open in repeating mode, thereby facilitating sniffing. This tool floods the switch’s CAM tables (131,000 per minute) by sending forged MAC entries. When the MAC table fills up, the switch converts to a hub-like operation where an attacker can monitor the data being broadcast.


Start flooding the CAM table with random MAC addresses:

	# macof -i eth0 -n 10
Note: -i: specifies the interface and -n: specifies the number of packets to be sent (here, 10).
Note: You can also target a single system by issuing the command macof -i eth0 -d [Target IP Address] (-d: Specifies the destination IP address).

Macof sends the packets with random MAC and IP addresses to all active machines in the local network. If you are using multiple targets, you will observe the same packets on all target machines.



### Perform a DHCP starvation attack using Yersinia

In a DHCP starvation attack, an attacker floods the DHCP server by sending a large number of DHCP requests and uses all available IP addresses that the DHCP server can issue. As a result, the server cannot issue any more IP addresses, leading to a Denial-of-Service (DoS) attack. Because of this issue, valid users cannot obtain or renew their IP addresses, and thus fail to access their network. This attack can be performed by using various tools such as Yersinia and Hyenae.

Yersinia is a network tool designed to take advantage of weaknesses in different network protocols such as DHCP. It pretends to be a solid framework for analyzing and testing the deployed networks and systems.


	# yersinia -I 		# open Yersinia in interactive mode.

	press h for help.
	q to exit the help options.
	F2 to select DHCP mode.
	x to list available attack options.
	1 to start a DHCP starvation attack.
	q to stop the attack and terminate Yersinia



### Perform ARP poisoning using arpspoof

ARP spoofing is a method of attacking an Ethernet LAN. ARP spoofing succeeds by changing the IP address of the attacker’s computer to the IP address of the target computer. A forged ARP request and reply packet find a place in the target ARP cache in this process. As the ARP reply has been forged, the destination computer (target) sends the frames to the attacker’s computer, where the attacker can modify them before sending them to the source machine (User A) in an MITM attack.

arpspoof redirects packets from a target host (or all hosts) on the LAN intended for another host on the LAN by forging ARP replies. This is an extremely effective way of sniffing traffic on a switch.


Informs the access point that the target system (10.10.1.11) has our MAC address (the MAC address of host machine (Parrot Security)):

	arpspoof -i eth0 -t 10.10.1.1 10.10.1.11 and press Enter.

(Here, 10.10.1.11 is IP address of the target system [Windows 11], and 10.10.1.1 is IP address of the access point or gateway)
Note: -i: specifies network interface and -t: specifies target IP address.


Informs the target system (10.10.1.11) that our host is the access point (10.10.1.1):

	arpspoof -i eth0 -t 10.10.1.11 10.10.1.1


### Perform an Man-in-the-Middle (MITM) attack using Cain & Abel

An attacker can obtain usernames and passwords using various techniques or by capturing data packets. By merely capturing enough packets, attackers can extract a target’s username and password if the victim authenticates themselves in public networks, especially on unsecured websites. Once a password is hacked, an attacker can use the password to interfere with the victim’s accounts such as by logging into the victim’s email account, logging onto PayPal and draining the victim’s bank account, or even change the password.

Another effective method for obtaining usernames and passwords is by using Cain & Abel to perform MITM attacks.

Cain & Abel is a password recovery tool that allows the recovery of passwords by sniffing the network and cracking encrypted passwords. The ARP poisoning feature of the Cain & Abel tool involves sending free spoofed ARPs to the network’s host victims. This spoofed ARP can make it easier to attack a middleman.


Note: In real-time, attackers use the ARP poisoning technique to perform sniffing on the target network. Using this method, attackers can steal sensitive information, prevent network and web access, and perform DoS and MITM attacks.



### Spoof a MAC address using TMAC and SMAC



### Spoof a MAC address of Linux machine using macchanger


It is not possible to change MAC address that is hard-coded on the NIC (Network interface controoller). However many drivers allow the MAC address to be changed. Some tools can make the operating system believe that the NIC has the MAC address of user's choice. Masking of the MAC address is known as MAC spoofing and involves changing the computer's identity.


	ifconfig eth0 down	# Turn off the network interface:

	macchanger --help

	macchanger -s eth0	# See the current MAC address of the machine.
Note: -s: prints the MAC address of the machine.

	macchanger -a eth0 	# set a random vendor MAC address to the network interface.
	macchanger -r eth0 	# set a random MAC address to the network interface.
	
	ifconfig eth0 up
	ifconfig eth0	# display



## Perform Network Sniffing using Various Sniffing Tools

### Perform password sniffing using Wireshark

You can use Wireshark to capture traffic on a remote interface.

Note: In real-time, when attackers gain the credentials of a victim’s machine, they attempt to capture its remote interface and monitor the traffic its user browses to reveal confidential user information.

On target Windows machine:

	Services -> Remote Packet Capture Protocol v.0 (experimental) -> right-click -> Start.

On attacker machine:

	Wireshark -> Capture Options -> Manage Interfaces… -> Remote Interfaces tab -> icon (+) (Add a remote host and its interface)
		-> Host: the IP address of the target machine; Port: 2002
		-> Authentication: Password authentication; target machine’s user credentials




### Analyze a network using the Omnipeek Network Protocol Analyzer

OmniPeek Network Analyzer provides real-time visibility and expert analysis of each part of the target network. It performs analysis, drills down, and fixes performance bottlenecks across multiple network segments. It includes analytic plug-ins that provide targeted visualization and search abilities.

An ethical hacker or pen tester can use this tool to monitor and analyze network traffic of the target network in real-time, identify the source location of that traffic, and attempt to obtain sensitive information as well as find any network loopholes.

	https://www.liveaction.com/products/omnipeek-network-protocol-analyzer/


### Analyze a network using the SteelCentral Packet Analyzer


SteelCentral Packet Analyzer provides a graphical console for high-speed packet analysis. It captures terabytes of packet data traversing the network, reads it, and displays it in a GUI. It can analyze multi-gigabyte recordings from locally presented trace files or on remote SteelCentral NetShark probes (physical, virtual, or embedded on SteelHeads), without a large file transfer, to identify anomalous network issues or diagnose and troubleshoot complex network and application performance issues down to the bit level.
