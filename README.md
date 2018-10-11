# MikroTik-AutoBan
This script parses log and add to blacklist IPv4 which caused error

---
## Attention!
#### The script was split into 3 different scripts:
* [MikroTik sshBan](https://github.com/teckerpro/MikroTik-sshBan)   *SSH/Telnet/FTP/Winbox/Web buteforce*
* [MikroTik IpsecBan](https://github.com/teckerpro/MikroTik-IPsecBan)    *IPsec bruteforce*
* [MikroTik pptpBan](https://github.com/teckerpro/MikroTik-pptpBan)    *PPTP bruteforce*
#### Use them
MikroTik AutoBan will not be developed

---
How to use

Create logging action

	/system logging action
	add memory-lines=60 name=YourAction target=memory
	/system logging
	add action=YourAction topics=error

Create script

	/system script
	add dont-require-permissions=no name=AutoBan owner=admin policy=\
		ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
		source=" Put Here Script "

Create firewall rule and Blacklist

	/ip firewall raw
	add action=drop chain=prerouting comment="Drop from blacklist" in-interface=ether-YourWANinterface \
		src-address-list=Blacklist
	/ip firewall address-list add list=YourBlacklist

Setup script

	bufferName is YourAction
	listName is YourBlacklist
	timeout is YourTimeout
	userName is YourLogin
	attempt is Attempts for login for your userName

Create scheduler witch your own interval, start-date and start-time

	/system scheduler
	add interval=1d name=AutoBan on-event="/system script run AutoBan" policy=\
		ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=oct/01/2018 start-time=11:00:00


This script adds to the blacklist IPv4 addresses which:

- attempt find password via SSH/Telnet/FTP/Web/Winbox
		
		login failure for user admin from 192.0.2.0 via ssh

- attempt find IPsec cipher/key

		192.0.2.0 failed to get valid proposal.
		192.0.2.0 failed to pre-process ph1 packet (side: 1, status 1).
		192.0.2.0 phase1 negotiation failed.
