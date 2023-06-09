CEH Notebook
============

Footprinting
------------

## Perform Footprinting Through Search Engines

As a professional ethical hacker or pen tester, your first step is to gather maximum information about the target organization by performing footprinting using search engines; you can perform advanced image searches, reverse image searches, advanced video searches, etc. Through the effective use of search engines, you can extract critical information about a target organization such as technology platforms, employee details, login pages, intranet portals, contact details, etc., which will help you in performing social engineering and other types of advanced system attacks.



Ggoogle Search:
    intitle:login site:eccouncil.org
	ec-council filetype:pdf ceh


cache: This operator allows you to view cached version of the web page. [cache:www.eccouncil.org]- Query returns the cached version of the website www.eccouncil.org

allinurl: This operator restricts results to pages containing all the query terms specified in the URL. [allinurl: EC-Council career]—Query returns only pages containing the words “EC-Council” and “career” in the URL

inurl: This operator restricts the results to pages containing the word specified in the URL [inurl: copy site:www.eccouncil.org]—Query returns only pages in EC-Council site in which the URL has the word “copy”

allintitle: This operator restricts results to pages containing all the query terms specified in the title. [allintitle: detect malware]—Query returns only pages containing the words “detect” and “malware” in the title

inanchor: This operator restricts results to pages containing the query terms specified in the anchor text on links to the page. [Anti-virus inanchor:Norton]—Query returns only pages with anchor text on links to the pages containing the word “Norton” and the page containing the word “Anti-virus”

allinanchor: This operator restricts results to pages containing all query terms specified in the anchor text on links to the page. [allinanchor: best cloud service provider]—Query returns only pages in which the anchor text on links to the pages contain the words “best,” “cloud,” “service,” and “provider”

link: This operator searches websites or pages that contain links to the specified website or page. [link:www.eccouncil.org]—Finds pages that point to EC-Council’s home page

related: This operator displays websites that are similar or related to the URL specified. [related:www.eccouncil.org]—Query provides the Google search engine results page with websites similar to eccouncil.org

info: This operator finds information for the specified web page. [info:eccouncil.org]—Query provides information about the www.eccouncil.org home page

location: This operator finds information for a specific location. [location: EC-Council]—Query give you results based around the term EC-Council



## Gather Information from Video Search Engines

Search a video on Youtube, and copy the link.

Go to https://mattw.io/youtube-metadata/ , paste the link and Enter to get the metadata such as published date and time, channel Id, title, etc.
Under the Thumbnail section you can find the reverse image search results, click on the Click to reverse image search button under any thumbnail.

You can use other video search engines such as Google videos (https://www.google.com/videohp), Yahoo videos (https://in.video.search.yahoo.com), etc.; video analysis tools such as EZGif (https://ezgif.com), VideoReverser.com (https://www.videoreverser.com) etc.; and reverse image search tools such as TinEye Reverse Image Search (https://tineye.com), Yahoo Image Search (https://images.search.yahoo.com), etc. to gather crucial information about the target organization.


### Gather Information from FTP Search Engines

NAPALM FTP indexer website: https://www.searchftps.net/

You can also use FTP search engines such as FreewareWeb FTP File Search (https://www.freewareweb.com) to gather crucial FTP information about the target organization.


### Gather Information from IoT Search Engines

Shodan: https://www.shodan.io/

You can also use Censys (https://censys.io), which is an IoT search engine, to gather information such as manufacturer details, geographical location, IP address, hostname, open ports, etc.



## Perform Footprinting Through Web Services

As a professional ethical hacker or pen tester, you should be able to extract a variety of information about your target organization from web services. By doing so, you can extract critical information such as a target organization’s domains, sub-domains, operating systems, geographic locations, employee details, emails, financial information, infrastructure details, hidden web pages and content, etc.

Using this information, you can build a hacking strategy to break into the target organization’s network and can carry out other types of advanced system attacks.


### Find the Company’s Domains and Sub-domains using Netcraft

Netcraft: https://www.netcraft.com
Navigate to the Resources -> Tools -> Site Report.
In the Network section, click on the website link (here, eccouncil.org) in the Domain field to view the subdomains


### Gather Personal Information using PeekYou Online People Search Service

PeekYou: https://www.peekyou.com

You can also use Spokeo (https://www.spokeo.com), pipl (https://pipl.com), Intelius (https://www.intelius.com), BeenVerified (https://www.beenverified.com), etc., people search services to gather personal information of key employees in the target organization.


### Gather an Email List using theHarvester

theHarvester -d airbus.com -l 200 -b baidu 

Note: In this command, -d specifies the domain or company name to search, -l specifies the number of results to be retrieved, and -b specifies the data source.

Note: Here, we specify Baidu search engine as a data source. You can specify different data sources (e.g., Baidu, bing, binaryedge, bingapi, censys, google, linkedin, twitter, virustotal, threatcrowd, crtsh, netcraft, yahoo, etc.) to gather information about the target.


### Gather Information using Deep and Dark Web Searching

Using Tor Brower to gather other relevant information about the target organization:

The Hidden Wiki is an onion site that works as a Wikipedia service of hidden websites. (http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki)

FakeID is an onion site for creating fake passports (http://ymvhtqya23wqpez63gyc3ke4svju3mqsby2awnhd3bk2e65izt7baqad.onion)

Cardshop is an onion site that sells cards with good balances (http://s57divisqlcjtsyutxjz2ww77vlbwpxgodtijcsrgsuts4js5hnxkhqd.onion)

You can also use tools such as ExoneraTor (https://metrics.torproject.org), OnionLand Search engine (https://onionlandsearchengine.com), etc. to perform deep and dark web browsing.


### Determine Target OS Through Passive Footprinting

Censys: https://search.censys.io/?q=

You can also use webservices such as Netcraft (https://www.netcraft.com), Shodan (https://www.shodan.io), etc. to gather OS information of target organization through passive footprinting.



## Perform Footprinting Through Social Networking Sites

As a professional ethical hacker, during information gathering, you need to gather personal information about employees working in critical positions in the target organization; for example, the Chief Information Security Officer, Security Architect, or Network Administrator. By footprinting through social networking sites, you can extract personal information such as name, position, organization name, current location, and educational qualifications. Further, you can find professional information such as company or business, current location, phone number, email ID, photos, videos, etc. The information gathered can be useful to perform social engineering and other types of advanced attacks.


### Gather Employees’ Information from LinkedIn using theHarvester

theHarvester -d eccouncil -l 200 -b linkedin

Note: In this command, -d specifies the domain or company name to search (here, eccouncil), -l specifies the number of results to be retrieved, and -b specifies the data source as LinkedIn.


### Gather Personal Information from Various Social Networking Sites using Sherlock

python3 sherlock satya nadella

You can also use tools such as Social Searcher (https://www.social-searcher.com), UserRecon (https://github.com), etc. to gather additional information related to the target company and its employees from social networking sites.


### Gather Information using Followerwonk

https://followerwonk.com/analyze

You can also use Hootsuite (https://www.hootsuite.com), Meltwater (https://www.meltwater.com), etc. to gather additional information related to the target company and its employees from social networking sites.


## Perform Website Footprinting

As a professional ethical hacker, you should be able to extract a variety of information about the target organization from its website; by performing website footprinting, you can extract important information related to the target organization’s website such as the software used and the version, operating system details, filenames, paths, database field names, contact details, CMS details, the technology used to build the website, scripting platform, etc. Using this information, you can further plan to launch advanced attacks on the target organization.

### Gather Information About a Target Website using Ping Command Line Utility

Using ping on Wind commands:

Try different values until you find the maximum frame size. For instance, ping www.certifiedhacker.com -f -l 1473 replies with Packet needs to be fragmented but DF set, and ping www.certifiedhacker.com -f -l 1472 replies with a successful ping. It indicates that 1472 bytes are the maximum frame size on this machine’s network.

Find the hop value by trying different TTL value to reach www.certifiedhacker.com.


### Gather Information About a Target Website using Photon

python3 photon.py -u http://www.certifiedhacker.com
Note: -u: specifies the target website (here, www.certifiedhacker.com).
The results obtained are saved in www.certifiedhacker.com directory under Photon folder.


python3 photon.py -u http://www.certifiedhacker.com -l 3 -t 200 --wayback 
Crawl the target website using URLs from archive.org.
Note: - -u: specifies the target website (here, www.certifiedhacker.com)
-l: specifies level to crawl (here, 3)
-t: specifies number of threads (here, 200)
--wayback: specifies using URLs from archive.org as seeds

Various other functionalities such as the cloning of the target website, extracting secret keys and cookies, obtaining strings by specifying regex pattern, etc. Using this information, the attackers can perform various attacks on the target website such as brute-force attacks, denial-of-service attacks, injection attacks, phishing attacks and social engineering attacks.


### Gather Information About a Target Website using Central Ops

https://centralops.net

You can also use tools such as Website Informer (https://website.informer.com), Burp Suite (https://portswigger.net), Zaproxy (https://www.zaproxy.org), etc. to perform website footprinting on a target website.


### Extract a Company’s Data using Web Data Extractor

Web Data Extractor on Windows

You can also use other web spiders such as ParseHub (https://www.parsehub.com), SpiderFoot (https://www.spiderfoot.net), etc. to extract the target organization’s data.


### Mirror a Target Website using HTTrack Web Site Copier

HTTrack Web Site Copier.

You can also use other mirroring tools such as Cyotek WebCopy (https://www.cyotek.com), etc. to mirror a target website.


### Gather Information About a Target Website using GRecon

GRecon is a Python tool that can be used to run Google search queries to perform reconnaissance on a target to find subdomains, sub-subdomains, login pages, directory listings, exposed documents, and WordPress entries.

Initialize:
python3 grecon.py


### Gather a Wordlist from the Target Website using CeWL

cewl -d 2 -m 5 https://www.certifiedhacker.com
Note: -d represents the depth to spider the website (here, 2) and -m represents minimum word length (here, 5).

A unique wordlist from the target website is gathered, as shown in the screenshot.
Note: The minimum word length is 5, and the depth to spider the target website is 2.

cewl -w wordlist.txt -d 2 -m 5 https://www.certifiedhacker.com and press Enter.
Note: -w - Write the output to the file (here, wordlist.txt)

This wordlist can be used further to perform brute-force attacks against the previously obtained emails of the target organization’s employees.



## Perform Email Footprinting

As a professional ethical hacker, you need to be able to track emails of individuals (employees) from a target organization for gathering critical information that can help in building an effective hacking strategy. Email tracking allows you to collect information such as IP addresses, mail servers, OS details, geolocation, information about service providers involved in sending the mail etc. By using this information, you can perform social engineering and other advanced attacks.


Email footprinting reveals information such as:.

Recipient's system IP address
The GPS coordinates and map location of the recipient
When an email message was received and read
Type of server used by the recipient
Operating system and browser information
If a destructive email was sent
The time spent reading the email
Whether or not the recipient visited any links sent in the email
PDFs and other types of attachments
If messages were set to expire after a specified time


### Gather Information about a Target by Tracing Emails using eMailTrackerPro

eMailTrackerPro

You can also use email tracking tools such as Infoga (https://github.com), Mailtrack (https://mailtrack.io), etc. to track an email and extract target information such as sender identity, mail server, sender’s IP address, location, etc.


## Perform Whois Footprinting

During the footprinting process, gathering information on the target IP address and domain obtained during previous information gathering steps is important. As a professional ethical hacker or penetration tester, you should be able to perform Whois footprinting on the target; this method provides target domain information such as the owner, its registrar, registration details, name server, contact information, etc. Using this information, you can create a map of the organization’s network, perform social engineering attacks, and obtain internal details of the network.

### Perform Whois Lookup using DomainTools

 http://whois.domaintools.com

You can also use other Whois lookup tools such as SmartWhois (https://www.tamos.com), Batch IP Converter (http://www.sabsoft.com), etc. to extract additional target Whois information.



## Perform DNS Footprinting

As a professional ethical hacker, you need to gather the DNS information of a target domain obtained during the previous steps. You need to perform DNS footprinting to gather information about DNS servers, DNS records, and types of servers used by the target organization. DNS zone data include DNS domain names, computer names, IP addresses, domain mail servers, service records, and much more about a target network.

Using this information, you can determine key hosts connected in the network and perform social engineering attacks to gather even more information.


### Gather DNS Information using nslookup Command Line Utility and Online Tool

Interactive mode in WIN command:

	nslookup
	
	> set type=a
	> www.certifiedhacker.com

If the response is coming from your local machine’s server (Google), but not the server that legitimately hosts the domain www.certifiedhacker.com; it is considered to be a non-authoritative answer. Here, the IP address of the target domain www.certifiedhacker.com is 162.241.216.11.

Since the result returned is non-authoritative, you need to obtain the domain's authoritative name server.

	
	> set type=cname		# The CNAME lookup is done directly against the domain's authoritative name server and lists the CNAME records for a domain.
	> certifiedhacker.com

This returns the domain’s authoritative name server (ns1.bluehost.com), along with the mail server address (dnsadmin.box5331.bluehost.com)

	> set type=a
	> ns1.bluehost.com 		# The primary name server that was returned in previous request 

The authoritative name server stores the records associated with the domain. So, if an attacker can determine the authoritative name server (primary name server) and obtain its associated IP address, he/she might attempt to exploit the server to perform attacks such as DoS, DDoS, URL Redirection, etc.


You can also perform the same operations using the NSLOOKUP online tool (http://www.kloth.net/services/nslookup.php).

You can also use DNS lookup tools such as DNSdumpster (https://dnsdumpster.com), DNS Records (https://network-tools.com), etc. to extract additional target DNS information.


### Perform Reverse DNS Lookup using Reverse IP Domain Check and DNSRecon

You Get Signal: find other domains/sites hosted on a web server
https://www.yougetsignal.com 


DNSRecon:

 ./dnsrecon.py -r 162.241.216.0-162.241.216.255   # Locate a DNS PTR record for IP addresses between 162.241.216.0 - 162.241.216.255.

Note: Here, we will use the IP address range, which includes the IP address of our target, that is, the certifiedhacker.com domain (162.241.216.11), which we acquired in the previous steps.

Note: -r option specifies the range of IP addresses (first-last) for reverse lookup brute force.


### Gather Information of Subdomain and DNS Records using SecurityTrails

SecurityTrails is an advanced DNS enumeration tool that is capable of creating a DNS map of the target domain network. It can enumerate both current and historical DNS records such as A, AAAA, NS, MX, SOA, and TXT, which helps in building the DNS structure. It also enumerates all the existing subdomains of the target domain using brute-force techniques.

https://securitytrails.com/


You can also use DNSChecker (https://dnschecker.org), and DNSdumpster (https://dnsdumpster.com), etc. to perform DNS footprinting on a target website.


## Perform Network Footprinting

With the IP address, hostname, and domain obtained in the previous information gathering steps, as a professional ethical hacker, your next task is to perform network footprinting to gather the network-related information of a target organization such as network range, traceroute, TTL values, etc. This information will help you to create a map of the target network and perform a man-in-the-middle attack.

### Locate the Network Range

ARIN:

https://www.arin.net/about/welcome/region

Enter the IP address to get the information about the network range along with the other information such as network type, registration information, etc.


### Perform Network Tracerouting in Windows and Linux Machines

In WIN CMD:

	tracert www.certifiedhacker.com		# to view the hops that the packets made before reaching the destination.
	tracert /?		# Help on tool


On Linux:

	traceroute www.certifiedhacker.com 


You can also use other traceroute tools such as VisualRoute (http://www.visualroute.com), Traceroute NG (https://www.solarwinds.com), etc. to extract additional network information of the target organization.


## Perform Footprinting using Various Footprinting Tools

The information gathered in the previous steps may not be sufficient to reveal the potential vulnerabilities of the target. There could be more information available that could help in finding loopholes in the target. As an ethical hacker, you should look for as much information as possible about the target using various tools. This lab activity will demonstrate what other information you can extract from the target using various footprinting tools.


### Footprinting a Target using Recon-ng

	recon-ng
	> marketplace install all	# Ignore the installation errors
	> modules search	# list modules (network discovery, exploitation, reconnaissance, etc.)
	> workspaces
	> workspaces create CEH
	> workspaces list
	> db insert domains		# To insert the domain to inspect
	> show domains
	
Harvest the hosts-related information associated with certifiedhacker.com by loading network reconnaissance modules such as brute_hosts, Netcraft, and Bing:

	> modules load brute	# Many modules related to brute force
	> modules load recon/domains-hosts/brute_hosts
	> run
	> back
	
Note: To resolve hosts using the Bing module, use the following commands:

	> back
	> modules load recon/domains-hosts/bing_domain_web
	> run

Perform a reverse lookup for each IP address (the IP address that is obtained during the reconnaissance process) to resolve to respective hostnames:

	> modules load reverse_resolve	# Many modules related to reverse/resolve
	> modules load recon/hosts-hosts/reverse_resolve
	> run
	> show hosts	# Displays all the hosts that are harvested so far.


Prepare a report containing all the hosts:

	> modules load reporting
	> modules load reporting/html
	> options set FILENAME /home/attacker/Desktop/results.html # Setting the report name as results.html
	> options set CREATOR [your name]
	> options set CUSTOMER Certifiedhacker Networks 	# (since you have performed network reconnaissance
	> run



Until now, we have used the Recon-ng tool to perform network reconnaissance on a target domain

Now, we will use Recon-ng to gather personnel information.

	> workspaces create reconnaissance

Set a domain and perform footprinting on it to extract contacts available in the domain.

	> modules load recon/domains-contacts/whois_pocs	# This module uses the ARIN Whois RWS to harvest POC data from Whois queries for the given domain.
	> info command		# View commands for this module
	> options set SOURCE facebook.com	# Add facebook.com as a target domain to gather contact details.
	> run


Until now, we have obtained contacts related to the domains. Note down these contacts’ names.

Now, we will use Recon-ng to extract a list of subdomains and IP addresses associated with the target URL.

	> modules load recon/domains-hosts/hackertarget
	> options set SOURCE certifiedhacker.com
	> run


### Footprinting a target using Maltego


In the left-pane of Maltego GUI, you can find the Entity Palette box, which contains a list of default built-in transforms. In the Infrastructure node under Entity Palette, observe a list of entities such as AS, DNS Name, Domain, IPv4 Address, URL, Website, etc.

Drag the Website entity onto the New Graph (1) window. Set the target website address (www.certifiedhacker.com).
Right-click the entity and select All Transforms.
The Run Transform(s) list appears; click To Domains [DNS].

Right-click the certifiedhacker.com entity and select All Transforms ---> To DNS Name [Using Name Schema diction…].
 This transform will attempt to test various name schemas against a domain and try to identify a specific name schema for the domain.
After identifying the name schema, attackers attempt to simulate various exploitation techniques to gain sensitive information related to the resultant name schemas. For example, an attacker may implement a brute-force or dictionary attack to log in to ftp.certifiedhacker.com and gain confidential information.

Right-click the certifiedhacker.com entity and select All Transforms --> To DNS Name - SOA (Start of Authority).
This returns the primary name server and the email of the domain administrator.
By extracting the SOA related information, attackers attempt to find vulnerabilities in their services and architectures and exploit them.

Right-click the certifiedhacker.com entity and select All Transforms --> To DNS Name - MX (mail server).
This transform returns the mail server associated with the certifiedhacker.com domain.
By identifying the mail exchanger server, attackers attempt to exploit the vulnerabilities in the server and, thereby, use it to perform malicious activities such as sending spam e-mails.

Right-click the certifiedhacker.com entity and select All Transforms --> To DNS Name - NS (name server).
This returns the name servers associated with the domain.
By identifying the primary name server, an attacker can implement various techniques to exploit the server and thereby perform malicious activities such as DNS Hijacking and URL redirection.

Right-click the entity and select All Transforms --> To IP Address [DNS].
By obtaining the IP address of the website, an attacker can simulate various scanning techniques to find open ports and vulnerabilities and, thereby, attempt to intrude in the network and exploit them.

Right-click the IP address entity and select All Transforms --> To location [city, country].
By obtaining the information related to geographical location, attackers can perform social engineering attacks by making voice calls (vishing) to an individual in an attempt to leverage sensitive information.

Right-click the www.certifiedhacker.com website entity and select All Transforms --> To Domains [DNS]. The domains corresponding to the website display.
Right-click the domain entity (certifiedhacker.com) and select All Transform --> To Entities from WHOIS [IBM Watson].
This transform returns the entities pertaining to the owner of the domain.
By obtaining this information, you can exploit the servers displayed in the result or simulate a brute force attack or any other technique to hack into the admin mail account and send phishing emails to the contacts in that account.

Apart from the aforementioned methods, you can perform footprinting on the critical employee from the target organization to gather additional personal information such as email addresses, phone numbers, personal information, image, alias, phrase, etc.

In the left-pane of the Maltego GUI, click the Personal node under Entity Palette to observe a list of entities such as Email Address, Phone Numbers, Image, Alias, Phrase, etc.

Apart from the transforms mentioned above, other transforms can track accounts and conversations of individuals who are registered on social networking sites such as Twitter. Extract all possible information.

By extracting all this information, you can simulate actions such as enumeration, web application hacking, social engineering, etc., which may allow you access to a system or network, gain credentials, etc.


### Footprinting a Target using OSRFramework


Use domainfy to check with the existing domains using words and nicknames. 

    domainfy -n [Domain Name] -t all 	# here, the target domain name is ECCOUNCIL

Note: -n: specifies a nickname or a list of nicknames to be checked. -t: specifies a list of top-level domains where nickname will be searched.

The tool will retrieve all the domains along with their IP addresses related to the target domain. Using this information, attackers can further find vulnerabilities in the subdomains of the target website and launch web application attacks.


Use searchfy to check for the existence of a given user details on different social networking platforms such as Github, Instagram and Keyserverubuntu. 

	searchfy -q "target user name or profile name" 	# The target user name or profile is searched in all the social media platforms.

Note: -q: specifies the query or list of queries to be performed.

Similarly, you can use following OSRFramework packages to gather more information about the target:
usufy - Gathers registered accounts with given usernames.
mailfy – Gathers information about email accounts
phonefy – Checks for the existence of a given series of phones
entify – Extracts entities using regular expressions from provided URLs


### Footprinting a Target using FOCA 

FOCA (Fingerprinting Organizations with Collected Archives) is a tool that reveals metadata and hidden information in scanned documents. These documents are searched for using three search engines: Google, Bing, and DuckDuckGo. The results from the three engines amounts to a lot of documents. FOCA examines a wide variety of records, with the most widely recognized being Microsoft Office, Open Office and PDF documents. It may also work with Adobe InDesign or SVG files. These archives may be on-site pages and can be downloaded and dissected with FOCA.



### Footprinting a Target using BillCipher

BillCipher is an information gathering tool for a Website or IP address. Using this tool, you can gather information such as DNS Lookup, Whois lookup, GeoIP Lookup, Subnet Lookup, Port Scanner, Page Links, Zone Transfer, HTTP Header, etc. Here, we will use the BillCipher tool to footprint a target website URL.

python3 billcipher.py


### Footprinting a Target using OSINT Framework

The OSINT Framework includes the following indicators with the available tools:
(T) - Indicates a link to a tool that must be installed and run locally
(D) - Google Dork
(R) - Requires registration
(M) - Indicates a URL that contains the search term and the URL itself must be edited manually

https://osintframework.com/


You can also use footprinting tools such as Recon-Dog (https://www.github.com), Grecon (https://github.com), Th3Inspector (https://github.com), Raccoon (https://github.com), Orb (https://github.com), etc. to gather additional information related to the target company.

