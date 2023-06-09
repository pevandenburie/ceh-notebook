CEH Notebook
============

Enumeration
-----------

Enumeration creates an active connection with the system and performs directed queries to gain more information about the target. It extracts lists of computers, usernames, user groups, ports, OSes, machine names, network resources, and services using various techniques. Enumeration techniques are conducted in an intranet environment.


## Perform NetBIOS Enumeration

As a professional ethical hacker or penetration tester, your first step in the enumeration of a Windows system is to exploit the NetBIOS API. NetBIOS enumeration allows you to collect information about the target such as a list of computers that belong to a target domain, shares on individual hosts in the target network, policies, passwords, etc. This data can be used to probe the machines further for detailed information about the network and host resources.


### Perform NetBIOS Enumeration using Windows Command-Line Utilities

Nbtstat helps in troubleshooting NETBIOS name resolution problems. The nbtstat command removes and corrects preloaded entries using several case-sensitive switches. Nbtstat can be used to enumerate information such as NetBIOS over TCP/IP (NetBT) protocol statistics, NetBIOS name tables for both the local and remote computers, and the NetBIOS name cache.

Net use connects a computer to, or disconnects it from, a shared resource. It also displays information about computer connections.

In WIN command, use NBT (NetBIOS over TCP/IP):

	nbtstat -a [IP address of the remote machine]
Note: In this command, -a displays the NetBIOS name table of a remote computer.

	nbtstat -c
Note: In this command, -c lists the contents of the NetBIOS name cache of the remote computer.
Note: It is possible to extract this information without creating a null session (an unauthenticated session).


Displays information about the target such as connection status, shared folder/drive and network information:

	net use


Using this information, the attackers can read or write to a remote computer system, depending on the availability of shares, or even launch a DoS attack.


### Perform NetBIOS Enumeration using NetBIOS Enumerator

NetBIOS Enumerator is a tool that enables the use of remote network support and several other techniques such as SMB (Server Message Block). It is used to enumerate details such as NetBIOS names, usernames, domain names, and MAC addresses for a given range of IP addresses.


### Perform NetBIOS Enumeration using an NSE Script

Display the open ports and services, along with their versions. Displayed under the Host script results section are details about the target system such as the NetBIOS name, NetBIOS user, and NetBIOS MAC address:

	nmap -sV -v --script nbstat.nse [Target IP Address]
Note: -sV detects the service versions, -v enables the verbose output (that is, includes all hosts and ports in the output), and --script nbstat.nse performs the NetBIOS enumeration.


Display the open NetBIOS port (137) and, under the Host script results section, NetBIOS details such as NetBIOS name, NetBIOS user, and NetBIOS MAC of the target system:

	nmap -sU -p 137 --script nbstat.nse [Target IP Address]
Note: -sU performs a UDP scan, -p specifies the port to be scanned, and --script nbstat.nse performs the NetBIOS enumeration.


Other tools may also be used to perform NetBIOS enumeration on the target network such as Global Network Inventory (http://www.magnetosoft.com), Advanced IP Scanner (https://www.advanced-ip-scanner.com), Hyena (https://www.systemtools.com), and Nsauditor Network Security Auditor (https://www.nsauditor.com).



## Perform SNMP Enumeration

As a professional ethical hacker or penetration tester, your next step is to carry out SNMP enumeration to extract information about network resources (such as hosts, routers, devices, and shares) and network information (such as ARP tables, routing tables, device-specific information, and traffic statistics).

Using this information, you can further scan the target for underlying vulnerabilities, build a hacking strategy, and launch attacks.


### Perform SNMP Enumeration using snmp-check

snmp-check is a tool that enumerates SNMP devices, displaying the output in a simple and reader-friendly format. The default community used is “public.” As an ethical hacker or penetration tester, it is imperative that you find the default community strings for the target device and patch them up.

	nmap -sU -p 161 [Target IP address]
Note: -sU performs a UDP scan and -p specifies the port to be scanned.

Obtain information about the target system:

	snmp-check [Target IP Address]
	

Attackers can further use this information to discover vulnerabilities in the target machine and further exploit them to launch attacks.



### Perform SNMP Enumeration using SoftPerfect Network Scanner

SoftPerfect Network Scanner can ping computers, scan ports, discover shared folders, and retrieve practically any information about network devices via WMI (Windows Management Instrumentation), SNMP, HTTP, SSH, and PowerShell.

The program also scans for remote services, registries, files, and performance counters. It can check for a user-defined port and report if one is open, and is able to resolve hostnames as well as auto-detect your local and external IP range. SoftPerfect Network Scanner offers flexible filtering and display options, and can export the NetScan results to a variety of formats, from XML to JSON. In addition, it supports remote shutdown and Wake-On-LAN.


You can also use other SNMP enumeration tools such as Network Performance Monitor (https://www.solarwinds.com), OpUtils (https://www.manageengine.com), PRTG Network Monitor (https://www.paessler.com), and Engineer’s Toolset (https://www.solarwinds.com) to perform SNMP enumeration on the target network.



### Perform SNMP Enumeration using SnmpWalk

SnmpWalk is a command line tool that scans numerous SNMP nodes instantly and identifies a set of variables that are available for accessing the target network. It is issued to the root node so that the information from all the sub nodes such as routers and switches can be fetched.

Displays all the OIDs, variables and other associated information:

	snmpwalk -v1 -c public [target IP]
	snmpwalk -v2c -c public [Target IP Address]
Note: –v: specifies the SNMP version number (1 or 2c or 3) and –c: sets a community string.


### Perform SNMP Enumeration using Nmap


Display information regarding SNMP server type and operating system details:

	nmap -sU -p 161 --script=snmp-sysdescr [target IP Address]
Note: -sU: specifies a UDP scan, -p: specifies the port to be scanned, and -–script: is an argument used to execute a given script (here, snmp-sysdescr).


Display a list of all the running SNMP processes along with the associated ports on the target machine:

	nmap -sU -p 161 --script=snmp-processes [target IP Address]
	

Display a list of all the applications running on the target machine:

	nmap -sU -p 161 --script=snmp-win32-software [target IP Address]


Display information about the Operating system, network interfaces, and applications that are installed on the target machine:

	nmap -sU -p 161 --script=snmp-interfaces [target IP Address]
	


## Perform LDAP Enumeration

As a professional ethical hacker or penetration tester, the next step after SNMP enumeration is to perform LDAP enumeration to access directory listings within Active Directory or other directory services. Directory services provide hierarchically and logically structured information about the components of a network, from lists of printers to corporate email directories. In this sense, they are similar to a company’s org chart.

LDAP enumeration allows you to gather information about usernames, addresses, departmental details, server names, etc.


### Perform LDAP Enumeration using Active Directory Explorer (AD Explorer)

Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. It can be used to navigate an AD database easily, define favorite locations, view object properties and attributes without having to open dialog boxes, edit permissions, view an object’s schema, and execute sophisticated searches that can be saved and re-executed.

Here, we will use the AD Explorer to perform LDAP enumeration on an AD domain and modify the domain user accounts.

You can also use other LDAP enumeration tools such as Softerra LDAP Administrator (https://www.ldapadministrator.com), LDAP Admin Tool (https://www.ldapsoft.com), LDAP Account Manager (https://www.ldap-account-manager.org), and LDAP Search (https://securityxploded.com) to perform LDAP enumeration on the target.


### Perform LDAP Enumeration using Python and Nmap

Display that the port 389 is open and being used by LDAP:

	nmap -sU -p 389 [Target IP address]
Note: -sU: performs a UDP scan and -p: specifies the port to be scanned.


Perform username enumeration on the target machine:

	nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' [Target IP Address]
Note: -p: specifies the port to be scanned, ldap-brute: to perform brute-force LDAP authentication. ldap.base: if set, the script will use it as a base for the password guessing attempts.
Nmap attempts to brute-force LDAP authentication and displays the usernames that are found



Using python3:

	python3
	>>> import ldap3
	>>> server=ldap3.Server(’[Target IP Address]’, get_info=ldap3.ALL,port=[Target Port])	# IP address is 10.10.1.22, and the port number is 389
	>>> connection=ldap3.Connection(server)
	>>> connection.bind()
	>>> server.info 	# gather information such as naming context or domain name. 

After receiving the naming context, we can make more queries to the server to extract more information:

	>>> connection.search(search_base='DC=CEH,DC=com',search_filter='(&(objectclass=*))',search_scope='SUBTREE', attributes='*')
	>>> connection.entries		# retrieve all the directory objects
	
	>>> connection.search(search_base='DC=CEH,DC=com',search_filter='(&(objectclass=person))',search_scope='SUBTREE', attributes='userpassword')
	>>> connection.entries		# dump the entire LDAP information
	
Using this information attackers can launch web application attacks and they can also gain access to the target machine.


### Perform LDAP Enumeration using ldapsearch

ldapsearch is a shell-accessible interface to the ldap_search_ext(3) library call. ldapsearch opens a connection to an LDAP server, binds the connection, and performs a search using the specified parameters. The filter should conform to the string representation for search filters as defined in RFC 4515. If not provided, the default filter, (objectClass=*), is used.

Gather details related to the naming contexts:

	ldapsearch -h [Target IP Address] -x -s base namingcontexts
Note: -x: specifies simple authentication, -h: specifies the host, and -s: specifies the scope.

Otain more information about the primary domain:

	ldapsearch -h [Target IP Address] -x -b “DC=CEH,DC=com”
Note: -x: specifies simple authentication, -h: specifies the host, and -b: specifies the base DN for search.


Retrieve information related to all the objects in the directory tree:

	ldapsearch -x -h [Target IP Address] -b "DC=CEH,DC=com" "objectclass=*"
Note: -x: specifies simple authentication, -h: specifies the host, and -b: specifies the base DN for search.


Attackers use ldapsearch for enumerating AD users. It allows attackers to establish connection with an LDAP server to carry out different searches using specific filters.


## Perform NFS Enumeration

As a professional ethical hacker or penetration tester, the next step after LDAP enumeration is to perform NFS enumeration to identify exported directories and extract a list of clients connected to the server, along with their IP addresses and shared data associated with them.

After gathering this information, it is possible to spoof target IP addresses to gain full access to the shared files on the server.


### Perform NFS Enumeration using RPCScan and SuperEnum

Check NFS service is running:

	nmap -p 2049 [Target IP Address]


Scan the target IP address for open NFS and other:

	echo "10.10.1.19" >> Target.txt 	# Possible to enter multiple IP addresses
	./superenum
Note: The scan will take approximately 15-20 mins to complete.


Check that port 2049 is open, and the NFS service is running on it:

	python3 rpc-scan.py [Target IP address] --rpc
Note: --rpc: lists the RPC (portmapper).


## Perform DNS Enumeration

As a professional ethical hacker or penetration tester, the next step after NFS enumeration is to perform DNS enumeration. This process yields information such as DNS server names, hostnames, machine names, usernames, IP addresses, and aliases assigned within a target domain.


### Perform DNS Enumeration using Zone Transfer

DNS zone transfer is the process of transferring a copy of the DNS zone file from the primary DNS server to a secondary DNS server. In most cases, the DNS server maintains a spare or secondary server for redundancy, which holds all information stored in the main server.

If the DNS transfer setting is enabled on the target DNS server, it will give DNS information; if not, it will return an error saying it has failed or refuses the zone transfer.

Retrieve information about all the DNS name servers of the target domain and displays it in the ANSWER SECTION:

	dig ns [Target Domain] 	# in this case, the target domain is www.certifiedhacker.com)
Note: In this command, ns returns name servers in the result
Note: On Linux-based systems, the dig command is used to query the DNS name servers to retrieve information about target host addresses, name servers, mail exchanges, etc


Display if the server is available, and if the Transfer succeed or fail:

	dig @[[NameServer]] [[Target Domain]] axfr  # in this example, the name server is ns1.bluehost.com and the target domain is www.certifiedhacker.com)
Note: In this command, axfr retrieves zone information.


After retrieving DNS name server information, the attacker can use one of the servers to test whether the target DNS allows zone transfers or not. In this case, zone transfers are not allowed for the target domain; this is why the command resulted in the message: Transfer failed. A penetration tester should attempt DNS zone transfers on different domains of the target organization.


Using NSLOOKUP on WIN command:

	nslookup
	> set querytype=soa
	
Type the target domain certifiedhacker.com

Note: set querytype=soa sets the query type to SOA (Start of Authority) record to retrieve administrative information about the DNS zone of the target domain certifiedhacker.com.

The result appears, displaying information about the target domain such as the primary name server and responsible mail addr

Check whether DNS server accept the zone transfer:

	ls -d [Name Server] 	# (in this example, the name is ns1.bluehost.com)
Note: In this command, ls -d requests a zone transfer of the specified name server.


After retrieving DNS name server information, the attacker can use one of the servers to test whether the target DNS allows zone transfers or not. In this case, the zone transfer was refused for the target domain. A penetration tester should attempt DNS zone transfers on different domains of the target organization.


### Perform DNS Enumeration using DNSSEC Zone Walking

DNSSEC zone walking is a DNS enumeration technique that is used to obtain the internal records of the target DNS server if the DNS zone is not properly configured. The enumerated zone information can assist you in building a host network map.

	./dnsrecon.py -d [Target domain] -z
Note: In this command, -d specifies the target domain and -z specifies that the DNSSEC zone walk be performed with standard enumeration.

Using the DNSRecon tool, the attacker can enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF, and TXT). These DNS records contain digital signatures based on public-key cryptography to strengthen authentication in DNS.

You can also use other DNSSEC zone enumerators such as LDNS (https://www.nlnetlabs.nl), nsec3map (https://github.com), nsec3walker (https://dnscurve.org), and DNSwalk (https://github.com) to perform DNS enumeration on the target domain.


### Perform DNS Enumeration using Nmap

List all the available DNS services on the target host along with their associated ports:

	nmap --script=broadcast-dns-service-discovery [Target Domain]	# (here the target domain is certifiedhacker.com)


List of all the subdomains associated with the target host along with their IP addresses:
 
	nmap -T4 -p 53 --script dns-brute [Target Domain]	# (here the target domain is certifiedhacker.com)
Note: -T4: specifies the timing template, -p: specifies the target port.


	nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='[Target Domain]'” 	# (here, the target domain is certifiedhacker.com).
	
	
Using this information, attackers can launch web application attacks such as injection attacks, brute-force attacks and DoS attacks on the target domain.


## Perform SMTP Enumeration

As an ethical hacker or penetration tester, the next step is to perform SMTP enumeration. SMTP enumeration is performed to obtain a list of valid users, delivery addresses, message recipients on an SMTP server.

Overview of SMTP Enumeration

The Simple Mail Transfer Protocol (SMTP) is an internet standard based communication protocol for electronic mail transmission. Mail systems commonly use SMTP with POP3 and IMAP, which enable users to save messages in the server mailbox and download them from the server when necessary. SMTP uses mail exchange (MX) servers to direct mail via DNS. It runs on TCP port 25, 2525, or 587.

### Perform SMTP Enumeration using Nmap

List of all the possible mail users on the target machine:

	nmap -p 25 --script=smtp-enum-users [Target IP Address]
Note: -p: specifies the port, and –script: argument is used to run a given script (here, the script is smtp-enum-users)


List of open SMTP relays on the target machine:

	nmap -p 25 --script=smtp-open-relay [Target IP Address]
Note: -p: specifies the port, and –script: argument is used to run a given script (here, the script is smtp-open-relay).


List of all the SMTP commands available in the Nmap directory:

	nmap -p 25 --script=smtp-commands [Target IP Address]

Using this information, the attackers can perform password spraying attacks to gain unauthorized access to the user accounts.


## Perform RPC, SMB, and FTP Enumeration

As an ethical hacker or penetration tester, you should use different enumeration techniques to obtain as much information as possible about the systems in the target network. This lab will demonstrate various techniques for extracting detailed information that can be used to exploit underlying vulnerabilities in target systems, and to launch further attacks.


### Perform SMB and RPC Enumeration using NetScanTools Pro

NetScanTools Pro is an integrated collection of Internet information-gathering and network-troubleshooting utilities for network professionals. The utility makes it easy to find IPv4/IPv6 addresses, hostnames, domain names, email addresses, and URLs related to the target system.


### Perform RPC, SMB, and FTP Enumeration using Nmap

Check that port 21 is open and the FTP service is running on target machine:

	nmap -p 21 [Target IP Address]
	

Display information regarding open ports, services along with their versions:

	nmap -T4 -A [Target IP Address] (here, the target IP address is 10.10.1.19) and press Enter.
Note: In this command, -T4: specifies the timing template (the number can be 0-5) and -A: specifies aggressive scan. The aggressive scan option supports OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (--traceroute).


Check that port 445 is open, and giving detailed information under the Host script results section about the running SMB:

	nmap -p 445 -A [Target IP Address]

Note: In this command, -p: specifies the port to be scanned, and -A: specifies aggressive scan. The aggressive scan option supports OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (--traceroute).


## Perform Enumeration using Various Enumeration Tools

The details obtained in the previous steps might not reveal all potential vulnerabilities in the target network. There may be more information available that could help attackers to identify loopholes to exploit. As an ethical hacker, you should use a range of tools to find as much information as possible about the target network’s systems. This lab activity will demonstrate further enumeration tools for extracting even more information about the target system.


### Enumerate Information using Global Network Inventory

Global Network Inventory is used as an audit scanner in zero deployment and agent-free environments. It scans single or multiple computers by IP range or domain, as defined by the Global Network Inventory host file.


### Enumerate Network Resources using Advanced IP Scanner

Advanced IP Scanner provides various types of information about the computers on a target network. The program shows all network devices, gives you access to shared folders, provides remote control of computers (via RDP and Radmin), and can even remotely switch computers off.


### Enumerate Information from Windows and Samba Hosts using Enum4linux

Enum4linux is a tool for enumerating information from Windows and Samba systems. It is used for share enumeration, password policy retrieval, identification of remote OSes, detecting if hosts are in a workgroup or a domain, user listing on hosts, listing group membership information, etc.

Enumerate the NetBIOS information of the target machine:

	enum4linux -u martin -p apple -n [Target IP Address]
Note: In this command, -u user: specifies the username to use and -p pass: specifies the password.
Note: Displays the NetBIOS information under the Nbtstat Information section.


Run the tool with the “get userlist” option:

	enum4linux -u martin -p apple -U [Target IP Address]
Note: In this command, -u user specifies the username to use, -p pass specifies the password and -U retrieves the userlist.
Note: Enumerates and displays data such as Target Information, Workgroup/Domain, domain SID (security identifier), and the list of users, along with their respective RIDs (relative identifier)


Obtain the OS information of the target:

	enum4linux -u martin -p apple -o [Target IP Address]
Note: In this command, -u user specifies the username to use, -p pass specifies the password and -o retrieves the OS information.


Enumerate the password policy information of our target machine. 

	enum4linux -u martin -p apple -P [Target IP Address]
Note: In this command, -u user specifies the username to use, -p pass specifies the password and -P retrieves the password policy information.


Enumerate the target machine’s group policy information:

	enum4linux -u martin -p apple -G [Target IP Address]
Note: In this command, -u user specifies the username to use, -p pass specifies the password and -G retrieves group and member list.


Enumerate the share policy information of our target machine:

	enum4linux -u martin -p apple -S [Target IP Address]
Note: In this command, -u user specifies the username to use, -p pass specifies the password and -S retrieves sharelist.


Using this information, attackers can gain unauthorized access to the user accounts and groups, and view confidential information in the shared drives.


