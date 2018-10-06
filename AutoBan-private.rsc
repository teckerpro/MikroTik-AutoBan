:local bufferName "achtung";
:local blacklistName "blacklist";
:local timeout 180d;			#Max Number = 35w3d13h13m56s

:local localIP "192.168.";		#192.168.0.0-192.168.255.255
:local localIPend 8;

#:local localIP "172.16.";		#172.16.0.0-172.31.255.255
#:local localIPend 7;

#:local localIP "10.";			#10.0.0.0-10.255.255.255
#:local localIPend 3;

:foreach line in=[/log find buffer=$bufferName] do={
	:do {
			#Bruteforce SSH/Telnet/FTP/Web/Winbox etc.
			:local content [/log get $line message];				#Парсит всю из лога с ошибкой
			:local position1 [:find $content "from " 0];			#Находит в этой строке позицию 'from '
			:local position2 [:find $content " via " 0];			#Находит в этой строке позицию ' via '
			:local badIP [:pick $content ($position1+5) $position2];	#Выделяет IP

			#Bruteforce IPsec key
			:set position1 0;
			:set position2 [:find $content " failed to get valid proposal" 0];			#Находит в этой строке позицию ' failed to get valid proposal'
			:set badIP [:pick $content $position1 $position2];	#Выделяет IP

			:if ([:pick $badIP 0 $localIPend] = $localIP)		#Проверяет локальный ли этот IP
			do={ :log info "Did you forgot your password\?"; :put "Did you forgot your password\?" }
			else={ /ip firewall address-list add list=$blacklistName address=$badIP timeout=$timeout };		#Иначе добавляет его в blacklist

		} on-error={ :log info "AutoBan Script has crashed"; :put "AutoBan Script has crashed" };		#Вывод информации в логи при ошибке
	}
