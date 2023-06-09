CEH Notebook
============

Social Engineering
------------------

## Perform Social Engineering using Various Techniques

There are three types of social engineering attacks: human-, computer-, and mobile-based.

- Human-based social engineering uses interaction to gather sensitive information, employing techniques such as impersonation, vishing, and eavesdropping
- Computer-based social engineering uses computers to extract sensitive information, employing techniques such as phishing, spamming, and instant messaging
- Mobile-based social engineering uses mobile applications to obtain information, employing techniques such as publishing malicious apps, repackaging legitimate apps, using fake security applications, and SMiShing (SMS Phishing)


### Sniff Credentials using the Social-Engineer Toolkit (SET)


The Social-Engineer Toolkit (SET) is an open-source Python-driven tool aimed at penetration testing via social engineering. SET is particularly useful to attackers, because it is freely available and can be used to carry out a range of attacks. For example, it allows attackers to draft email messages, attach malicious files, and send them to a large number of people using spear phishing. Moreover, SET’s multi-attack method allows Java applets, the Metasploit browser, and Credential Harvester/Tabnabbing to be used simultaneously. SET categorizes attacks according to the attack vector used such as email, web, and USB.


	# setoolkit 
	> 1			# select Solical engineering attacks
	> 2			# web site attack vector
	> 3 		# Credentials harvest attack method
	> 2			# Sit cloner
	> 10.10.1.13	# local address to receive the POST
	> http://www.moviescope.com		# login web page of the site to clone. Could be facebook.

Target must be fooled by an URL showking moviespace.com but redirecting to http://10.10.1.13.


## Detect a Phishing Attack

### Detect Phishing using Netcraft

The Netcraft anti-phishing community is a giant neighborhood watch scheme, empowering the most alert and most expert members to defend everyone within the community against phishing attacks. The Netcraft Extension provides updated and extensive information about sites that users visit regularly; it also blocks dangerous sites. This information helps users to make an informed choice about the integrity of those sites.


https://www.netcraft.com/apps/


### Detect Phishing using PhishTank

PhishTank is a free community site on which anyone can submit, verify, track, and share phishing data. As the official website notes, “it is a collaborative clearing house for data and information about phishing on the Internet.” PhishTank provides an open API for developers and researchers to integrate anti-phishing data into their applications.

https://www.phishtank.com


## Audit Organization's Security for Phishing Attacks

### Audit Organization's Security for Phishing Attacks using OhPhish

OhPhish is a web-based portal for testing employees’ susceptibility to social engineering attacks. It is a phishing simulation tool that provides an organization with a platform to launch phishing simulation campaigns on its employees. The platform captures the responses and provides MIS reports and trends (on a real-time basis) that can be tracked according to the user, department, or designation.