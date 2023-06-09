CEH Notebook
============

Scanning
--------

Scan via ICMP ECHO ping sweep:

nmap -sP 10.10.1.2/24

nmap -sn -PR [Target IP Address]
Note: -sn: disables port scan and -PR: performs ARP ping scan.
Note: The ARP ping scan probes ARP request to target host; an ARP response means that the host is active.


nmap -sn -PU [Target IP Address]
Note: -PU: performs the UDP ping scan.
Note: The UDP ping scan sends UDP packets to the target host; a UDP response means that the host is active. If the target host is offline or unreachable, various error messages such as “host/network unreachable” or “TTL exceeded” could be returned.


ICMP ECHO ping scan:
nmap -sn -PE [Target IP Address]
Note: -PE: performs the ICMP ECHO ping scan.
Note: The ICMP ECHO ping scan involves sending ICMP ECHO requests to a host. If the target host is alive, it will return an ICMP ECHO reply. This scan is useful for locating active devices or determining if the ICMP is passing through a firewall.

ICMP ECHO ping sweep to discover live hosts from a range of target IP addresses
nmap -sn -PE [Target Range of IP Addresses]
Note: The ICMP ECHO ping sweep is used to determine the live hosts from a range of IP addresses by sending ICMP ECHO requests to multiple hosts. If a host is alive, it will return an ICMP ECHO reply.


 nmap -sn -PP [Target IP Address]
Note: -PP: performs the ICMP timestamp ping scan.
Note: ICMP timestamp ping is an optional and additional type of ICMP ping whereby the attackers query a timestamp message to acquire the information related to the current time from the target host machine.


Apart from the aforementioned network scanning techniques, you can also use the following scanning techniques to perform a host discovery on a target network.

ICMP Address Mask Ping Scan: This technique is an alternative for the traditional ICMP ECHO ping scan, which are used to determine whether the target host is live specifically when administrators block the ICMP ECHO pings.

# nmap -sn -PM [target IP address]

TCP SYN Ping Scan: This technique sends empty TCP SYN packets to the target host, ACK response means that the host is active.

# nmap -sn -PS [target IP address]

TCP ACK Ping Scan: This technique sends empty TCP ACK packets to the target host; an RST response means that the host is active.

# nmap -sn -PA [target IP address]

IP Protocol Ping Scan: This technique sends different probe packets of different IP protocols to the target host, any response from any probe indicates that a host is active.

# nmap -sn -PO [target IP address]




## Perform Port and Service Discovery
Lab Scenario

As a professional ethical hacker or a pen tester, the next step after discovering active hosts in the target network is to scan for open ports and services running on the target IP addresses in the target network. This discovery of open ports and services can be performed via various port scanning tools and techniques.


Perform Port Scanning using sx Tool
sx arp [Target subnet]
sx arp [Target subnet] --json | tee arp.cache
Note: Before the actual scan, sx explicitly creates an ARP cache file which is a simple text file containing a JSON string on each line and has the same JSON fields as the ARP scan JSON output. The protocols such as TCP and UDP read the ARP cache file from stdin and then begin the scan.

List all the open TCP ports on the target machine
cat arp.cache | sx tcp -p 1-65535 [Target IP address]
Note: tcp: performs a TCP scan, -p: specifies the range of ports to be scanned (here, the range is 1-65535).

List all the open UDP ports on the target machine
cat arp.cache | sx udp --json -p [Target Port] 10.10.1.11
Note: According to RFC1122, a host should generate Destination Unreachable messages with code: 2 (Protocol Unreachable), when the designated transport protocol is not supported; or 3 (Port Unreachable), when the designated transport protocol (e.g., UDP) is unable to demultiplex the datagram but has no protocol mechanism to inform the sender.
Note: sx does not return any code in the above command, which states that the target port is open.



Explore Various Network Scanning Techniques using Nmap


UDP Scan
nmap -sU -v [Target IP Address]


Connect Scan
nmap -sT -v [Target IP Address]
Note: -sT: performs the TCP connect/full open scan and -v: enables the verbose output (include all hosts and ports in the output).
Note: TCP connect scan completes a three-way handshake with the target machine. In the TCP three-way handshake, the client sends a SYN packet, which the recipient acknowledges with the SYN+ACK packet. In turn, the client acknowledges the SYN+ACK packet with an ACK packet to complete the connection. Once the handshake is completed, the client sends an RST packet to end the connection.


SYN Stealth Scan
nmap -sS -v [Target IP Address]
Note: -sS: performs the stealth scan/TCP half-open scan and -v: enables the verbose output (include all hosts and ports in the output).
Note: The stealth scan involves resetting the TCP connection between the client and server abruptly before completion of three-way handshake signals, and hence leaving the connection half-open. This scanning technique can be used to bypass firewall rules, logging mechanisms, and hide under network traffic.


Xmas scan
nmap -sX -v [Target IP Address]
Note: -sX: performs the Xmas scan and -v: enables the verbose output (include all hosts and ports in the output).
Note: Xmas scan sends a TCP frame to a target system with FIN, URG, and PUSH flags set. If the target has opened the port, then you will receive no response from the target system. If the target has closed the port, then you will receive a target system reply with an RST.


TCP Mainmon Scan
nmap -sM -v [Target IP Address]
Note: -sM: performs the TCP Maimon scan and -v: enables the verbose output (include all hosts and ports in the output).
Note: In the TCP Maimon scan, a FIN/ACK probe is sent to the target; if there is no response, then the port is Open|Filtered, but if the RST packet is sent as a response, then the port is closed.


ACK flag probe scan
nmap -sA -v [Target IP Address]
Note: -sA: performs the ACK flag probe scan and -v: enables the verbose output (include all hosts and ports in the output).
Note: The ACK flag probe scan sends an ACK probe packet with a random sequence number; no response implies that the port is filtered (stateful firewall is present), and an RST response means that the port is not filtered.


UDP Scan
nmap -sU -v [Target IP Address] 
Note: -sU: performs the UDP scan and -v: enables the verbose output (include all hosts and ports in the output).
Note: The UDP scan uses UDP protocol instead of the TCP. There is no three-way handshake for the UDP scan. It sends UDP packets to the target host; no response means that the port is open. If the port is closed, an ICMP port unreachable message is received.


Null Scan
nmap -sN -v [Target IP Address]


Other techniques:

IDLE/IPID Header Scan: A TCP port scan method that can be used to send a spoofed source address to a computer to discover what services are available.

   # nmap -sI -v [target IP address]

SCTP INIT Scan: An INIT chunk is sent to the target host; an INIT+ACK chunk response implies that the port is open, and an ABORT Chunk response means that the port is closed.

   # nmap -sY -v [target IP address]

SCTP COOKIE ECHO Scan: A COOKIE ECHO chunk is sent to the target host; no response implies that the port is open and ABORT Chunk response means that the port is closed.

   # nmap -sZ -v [target IP address]



## Service Discovery


nmap -sV [Target IP Address]
Note: -sV: detects service versions.
Note: Service version detection helps you to obtain information about the running services and their versions on a target system. Obtaining an accurate service version number allows you to determine which exploits the target system is vulnerable to.


nmap -sA [Target IP Address]
Note: -A: enables aggressive scan. The aggressive scan option supports OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (--traceroute). You should not use -A against target networks without permission.



## Explore Various Network Scanning Techniques using Hping3

hping3 -A [Target IP Address] -p 80 -c 5
Note: In this command, -A specifies setting the ACK flag, -p specifies the port to be scanned (here, 80), and -c specifies the packet count (here, 5).
Note: The ACK scan sends an ACK probe packet to the target host; no response means that the port is filtered. If an RST response returns, this means that the port is closed.


hping3 -8 0-100 -S [Target IP Address] -V
Note: In this command, -8 specifies a scan mode, -p specifies the range of ports to be scanned (here, 0-100), and -V specifies the verbose mode.
Note: The SYN scan principally deals with three of the flags: SYN, ACK, and RST. You can use these three flags for gathering illegal information from servers during the enumeration process.


hping3 -F -P -U [Target IP Address] -p 80 -c 5
Note: In this command, -F specifies setting the FIN flag, -P specifies setting the PUSH flag, -U specifies setting the URG flag, -c specifies the packet count (here, 5), and -p specifies the port to be scanned (here, 80).
Note: FIN, PUSH, and URG scan the port on the target IP address. If a port is open on the target, you will receive a response. If the port is closed, Hping will return an RST response.



hping3 --scan 0-100 -S [Target IP Address]
Note: In this command, --scan specifies the port range to scan, 0-100 specifies the range of ports to be scanned, and -S specifies setting the SYN flag.
Note: In the TCP stealth scan, the TCP packets are sent to the target host; if a SYN+ACK response is received, it indicates that the ports are open.


ICMP scan
hping3 -1 [Target IP Address] -p 80 -c 5
Note: In this command, -1 specifies ICMP ping scan, -c specifies the packet count (here, 5), and -p specifies the port to be scanned (here, 80).

The results demonstrate that hping has sent ICMP echo requests to 10.10.1.22 and received ICMP replies which determines that the host is up.


Other scans:

Entire subnet scan for live host: hping3 -1 [Target Subnet] --rand-dest -I eth0

UDP scan: hping3 -2 [Target IP Address] -p 80 -c 5



## Perform OS Discovery

As a professional ethical hacker or a pen tester, the next step after discovering the open ports and services running on the target range of IP addresses is to perform OS discovery. Identifying the OS used on the target system allows you to assess the system’s vulnerabilities and the exploits that might work on the system to perform additional attacks.


### Identify the Target System’s OS with Time-to-Live (TTL) and TCP Window Sizes

Perform a ping on target machine. based on TTL, deduce the OS:

OS				TTL		TCP Window Size
Linux			64		5840
FreeBSD			64		65535
OpenBSD			255		16384
Windows			128		65535 bytes to 1Gb
Cisco Routers	255		4128
Solaris			255		8760
AIX				255		16384


### Perform OS Discovery using Nmap Script Engine (NSE)

nmap -A [Target IP Address]
Note: -A: to perform an aggressive scan.
Note: The scan takes approximately 10 minutes to complete.
The scan results appear, displaying the open ports and running services along with their versions and target details such as OS, computer name, NetBIOS computer name, etc. under the Host script results section.


nmap -O [Target IP Address]
Note: -O: performs the OS discovery.
The scan results appear, displaying information about open ports, respective services running on the open ports, and the name of the OS running on the target system.


nmap --script smb-os-discovery.nse [Target IP Address]
Note: --script: specifies the customized script and smb-os-discovery.nse: attempts to determine the OS, computer name, domain, workgroup, and current time over the SMB protocol (ports 445 or 139).
The scan results appear, displaying the target OS, computer name, NetBIOS computer name, etc. details under the Host script results section.


### Perform OS Discovery using Unicornscan

unicornscan [Target IP Address] -Iv
Note: In this command, -I specifies an immediate mode and v specifies a verbose mode.


## Scan beyond IDS and Firewall

As a professional ethical hacker or a pen tester, the next step after discovering the OS of the target IP address(es) is to perform network scanning without being detected by the network security perimeters such as the firewall and IDS. IDSs and firewalls are efficient security mechanisms; however, they still have some security limitations. You may be required to launch attacks to exploit these limitations using various IDS/firewall evasion techniques such as packet fragmentation, source routing, IP address spoofing, etc. Scanning beyond the IDS and firewall allows you to evaluate the target network’s IDS and firewall security.

Techniques to evade IDS/firewall:

Packet Fragmentation: Send fragmented probe packets to the intended target, which re-assembles it after receiving all the fragments
Source Routing: Specifies the routing path for the malformed packet to reach the intended target
Source Port Manipulation: Manipulate the actual source port with the common source port to evade IDS/firewall
IP Address Decoy: Generate or manually specify IP addresses of the decoys so that the IDS/firewall cannot determine the actual IP address
IP Address Spoofing: Change source IP addresses so that the attack appears to be coming in as someone else
Creating Custom Packets: Send custom packets to scan the intended target beyond the firewalls
Randomizing Host Order: Scan the number of hosts in the target network in a random order to scan the intended target that is lying beyond the firewall
Sending Bad Checksums: Send the packets with bad or bogus TCP/UPD checksums to the intended target
Proxy Servers: Use a chain of proxy servers to hide the actual source of a scan and evade certain IDS/firewall restrictions
Anonymizers: Use anonymizers that allow them to bypass Internet censors and evade certain IDS and firewall rules


### Scan beyond IDS/Firewall using Various Evasion Techniques

nmap -f [Target IP Address]
Note: -f switch is used to split the IP packet into tiny fragment packets.
Note: Packet fragmentation refers to the splitting of a probe packet into several smaller packets (fragments) while sending it to a network. When these packets reach a host, IDSs and firewalls behind the host generally queue all of them and process them one by one. However, since this method of processing involves greater CPU consumption as well as network resources, the configuration of most of IDSs makes it skip fragmented packets during port scans.


nmap -g 80 [Target IP Address]
Note: In this command, you can use the -g or --source-port option to perform source port manipulation.
Note: Source port manipulation refers to manipulating actual port numbers with common port numbers to evade IDS/firewall: this is useful when the firewall is configured to allow packets from well-known ports like HTTP, DNS, FTP, etc.


nmap -mtu 8 [Target IP Address]
Note: In this command, -mtu: specifies the number of Maximum Transmission Unit (MTU) (here, 8 bytes of packets).
Note: Using MTU, smaller packets are transmitted instead of sending one complete packet at a time. This technique evades the filtering and detection mechanism enabled in the target machine.


nmap -D RND:10 [Target IP Address]
Note: In this command, -D: performs a decoy scan and RND: generates a random and non-reserved IP addresses (here, 10).
Note: The IP address decoy technique refers to generating or manually specifying IP addresses of the decoys to evade IDS/firewall. This technique makes it difficult for the IDS/firewall to determine which IP address was actually scanning the network and which IP addresses were decoys. By using this command, Nmap automatically generates a random number of decoys for the scan and randomly positions the real IP address between the decoy IP addresses.


nmap -sT -Pn --spoof-mac 0 [Target IP Address]
Note: In this command --spoof-mac 0 represents randomizing the MAC address, -sT: performs the TCP connect/full open scan, -Pn is used to skip the host discovery.
Note: MAC address spoofing technique involves spoofing a MAC address with the MAC address of a legitimate user on the network. This technique allows you to send request packets to the targeted machine/network pretending to be a legitimate host.


### Create Custom UDP and TCP Packets using Hping3 to Scan beyond the IDS/Firewall

hping3 [Target IP Address] --udp --rand-source --data 500
Note: Here, --udp specifies sending the UDP packets to the target host, --rand-source enables the random source mode and --data specifies the packet body size.


hping3 -S [Target IP Address] -p 80 -c 5 (here, target IP address is 10.10.1.11), and then press Enter.
Note: Here, -S specifies the TCP SYN request on the target machine, -p specifies assigning the port to send the traffic, and -c is the count of the packets sent to the target machine.


hping3 [Target IP Address] --flood
Note: --flood: performs the TCP flooding.



## Perform Network Scanning using Metasploit

If needed, initialize DB:

    nsfdb init
	service postgresql restart


    msfconsole
	> db_status    # check DB status
	
    > nmap -Pn -sS -A -oX Test 10.10.1.0/24    # Scan the subnet
	> db_import Test		# Import the nmap results from the DB

    > hosts
	> services    # or db_services

    > search portscan   # metasploit port scanning module
	> use auxiliary/scanner/portscan/syn   # module to perform an SYN scan on the target systems
	> set INTERFACE eth0
	> set PORTS 80
	> set RHOSTS 10.10.1.5-23
	> set THREADS 50
	> run
	
	use auxiliary/scanner/portscan/tcp
	hosts -R   # or `set RHOSTS [Target IP Address]` 
	# to automatically set this option with the discovered hosts present in our database
	run
	
	> back
	
	use auxiliary/scanner/smb/smb_version  # module to run a SMB version scan
	set RHOSTS 10.10.1.5-23
	set THREADS 11
	run
	
	
Explore various modules of Metasploit such as FTP module.



Some useful ports to know:

21	FTP
137	NetBIOS
161	SNMP
389	LDAP
445	SMB (Server Message Block)