:local bufferName "achtung";
:local listName "blacklist";
:local timeout 180d;
:local userName "alex";

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

			#Bruteforce SSH/Telnet/FTP/Web/Winbox
			:if ([:find $content "login failure for user"] >= 0)\
			do={
				:set position1 [:find $content "from "];
				:set position2 [:find $content " via "];
				:set badIP [:pick $content ($position1+5) $position2];
				:set service [:pick $content ($position2+5) [:len $content]];
				:set user [:pick $content 23 ($position1-1)];

				:if ($userName = $user and $badIP = $prevBadIP and $counter < 4)\
				do={
					:log warning "$user, $badIP is it you?";
					:set counter ($counter+1);
					}
				:if ($counter >= 3)\
				do={
					:log warning "$prevBadIP is not you! It will be banned";
					/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan ($content)";
					:log warning "IP $badIP has been banned like a bitch!";
					}

				#check isLocal and isExistsInBlacklist
				:if ([:pick $badIP 0 $localIPend] != $localIP   and   ($userName != $user)   and   ([:len [/ip firewall address-list find address=$badIP and list=$listName]] <= 0))\
				do={
					:if ($service = "ssh")\
					do={
						/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan ssh";
						:log warning "IP $badIP has been banned (ssh)";
						}

					:if ($service = "ftp")\
					do={
						/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan ftp";
						:log warning "IP $badIP has been banned (ftp)";
						}

					:if ($service = "telnet")\
					do={
						/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan telnet";
						:log warning "IP $badIP has been banned (telnet)";
						}

					:if ($service = "winbox")\
					do={
						/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan winbox";
						:log warning "IP $badIP has been banned (winbox)";
						}

					:if ($service = "web")\
					do={
						/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan web";
						:log warning "IP $badIP has been banned (web)";
						} else={ :log error "AutoBan Script coldn't check the service"; }
					}
					:set prevBadIP $badIP;
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
					:log warning "IP $badIP has been banned (IPsec)";
					}
			}

		} on-error={ :log error "AutoBan Script has crashed"; }
	}
:log info "AutoBan Script was executed properly";