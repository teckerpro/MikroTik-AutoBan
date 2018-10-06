# MikroTik-AutoBan
This script parses log and add to blacklist IPv4 which caused error

How to use

Create logging action

/system logging action
add memory-lines=60 name=YourAction target=memory
/system logging
add action=YourAction topics=error,critical

Create script

/system script
add dont-require-permissions=no name=AutoBan owner=admin policy=\
	ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
	source=" Put Here Script "

Create scheduler witch your own interval, start-date and start-time

/system scheduler
add interval=1d name=AutoBan on-event="/system script run AutoBan" policy=\
    ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=oct/01/2018 start-time=11:00:00


Скрипт вносит в черный список IPv4 адреса:

- Подбирающие пароль по SSH/Telnet/FTP/Web/Winbox
		
		login failure for user admin from IPv4.IPv4.IPv4.IPv4 via ssh

- Подбирающие IPsec ключ

		IPv4.IPv4.IPv4.IPv4 failed to get valid proposal.
		IPv4.IPv4.IPv4.IPv4 failed to pre-process ph1 packet (side: 1, status 1).
		IPv4.IPv4.IPv4.IPv4 phase1 negotiation failed.
