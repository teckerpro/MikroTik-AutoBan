:local bufferName "achtung";
:local blacklistName "blacklist";
:local timeout 180d;

:foreach line in=[/log find buffer=$bufferName] do={
	:do {
			:local content [/log get $line message];
			:local position1 "";
			:local position2 "";
			:local badIP "";

			:local lIPb1 [:pick $badIP 0 8];		#192.168.0.0-192.168.255.255
			:local lIPb2 [:pick $badIP 0 7];		#172.16.0.0-172.31.255.255
			:local lIPb3 [:pick $badIP 0 3];		#10.0.0.0-10.255.255.255
			
			#Bruteforce SSH/Telnet/FTP/Web/Winbox etc.
			:if ([:find $content "login failure for user"] >= 0)\
			do={
				:set position1 [:find $content "from "];
				:set position2 [:find $content " via "];
				:set badIP [:pick $content ($position1+5) $position2];

				:if ( ($lIPb1 != "192.168." || $lIPb3 != "10." ||\
				$lIPb2 != "172.16." || $lIPb2 != "172.17." || $lIPb2 != "172.18." || $lIPb2 != "172.19." ||\ 
				$lIPb2 != "172.20." || $lIPb2 != "172.21." || $lIPb2 != "172.22." || $lIPb2 != "172.23." ||\
				$lIPb2 != "172.24." || $lIPb2 != "172.25." || $lIPb2 != "172.26." || $lIPb2 != "172.27." ||\ 
				$lIPb2 != "172.28." || $lIPb2 != "172.29." || $lIPb2 != "172.30." || $lIPb2 != "172.31.")\
				and ([:len [/ip firewall address-list find address=$badIP and list=$listName]] <= 0) )
				do={
				/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by AutoBan SSH and etc";
				:log warning "IP $badIP has been banned (SSH and etc)";
				}
			}

			#Bruteforce IPsec
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