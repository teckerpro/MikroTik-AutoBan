:local bufferName "achtung";
:local listName "blacklist";
:local timeout 180d;
:local userName "alex";
:local attempt 3; # Attempts for your userName

:local localIP "192.168.";		#192.168.0.0-192.168.255.255
:local localIPend 8;
#:local localIP "172.16.";		#172.16.0.0-172.31.255.255
#:local localIPend 7;
#:local localIP "10.";			#10.0.0.0-10.255.255.255
#:local localIPend 3;
:local counter 0;
:local prevBadIP "";

:foreach line in=[/log find buffer=$bufferName] do={
	:do {
			:local content [/log get $line message];
			:local position1 "";
			:local position2 "";
			:local badIP "";
			:local service "";
			:local user "";
			:local localPrefix "";

			#Bruteforce SSH/Telnet/FTP/Web/Winbox
			:if ([:find $content "login failure for user"] >= 0)\
			do={
				:set position1 [:find $content "from "];
				:set position2 [:find $content " via "];
				:set badIP [:pick $content ($position1+5) $position2];
				:set localPrefix [:pick $badIP 0 $localIPend];
				:set service [:pick $content ($position2+5) [:len $content]];
				:set user [:pick $content 23 ($position1-1)];

				#check #1: Is it local address and Is it you or not you?
				:if ( ($localPrefix != $localIP)   and   ($userName = $user)   and   ($badIP = $prevBadIP)   and   ($counter <= $attempt)   and   ([:len [/ip firewall address-list find address=$badIP and list=$listName]] <= 0) )\
				do={
					:log warning "$user, ip $badIP is it you? Attempt #$counter";
					:set counter ($counter+1);
					}
				:if ($counter >= $attempt)\
				do={
					:log warning "ip $prevBadIP is not you! It will be banned!";
					/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan ($content)";
					:log warning "ip $badIP has been banned like a bitch!";
					:set counter 0;
					}
				:if ($counter != 0 and $prevBadIP != $badIP)	do={ :set counter 0; }

				#check #2: Is it local address and Is it exists in blacklist?
				:if ( ($localPrefix != $localIP)   and   ($userName != $user)   and   ([:len [/ip firewall address-list find address=$badIP and list=$listName]] <= 0))\
				do={
					/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan $service";
					:log warning "ip $badIP has been banned ($service)";
					}

					:set prevBadIP $badIP; #for check #1
				}

			#Bruteforce IPsec
			:if ([:find $content "failed to get valid proposal"] >= 0)\
			do={
				:set position1 0;
				:set position2 [:find $content " failed to get valid proposal"];
				:set badIP [:pick $content $position1 $position2];

				:if ([:len [/ip firewall address-list find address=$badIP and list=$listName]] <= 0)\
				do={
					/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan IPsec";
					:log warning "ip $badIP has been banned (IPsec)";
					}
			}

		} on-error={ :log error "AutoBan Script has crashed"; }
	}
:log info "AutoBan Script was executed properly";