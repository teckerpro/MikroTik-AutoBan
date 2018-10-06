:local bufferName "achtung";
:local blacklistName "blacklist";
:local timeout 180d;			#Max Number = 35w3d13h13m56s

:foreach line in=[/log find buffer=$bufferName] do={
	:do {
			:local content [/log get $line message];		#Парсит всю из лога с ошибкой (строка1)
			:local position1 [:find $content "from" 0];		#Ищет где в этой строке начинается 'from'
			:local position2 [:find $content "via" 0];		#Ищет где в этой строке начинается 'via'

			:local badIPline "";
			:local badIP "";
			:local badIP1 "";

			:set badIPline [:pick $content $position1 $position2];		#Выбирает из строки1 подстроку, с IP адесом (from 8.8.8.8 via) (строка2)

			:local badIPfrom [:find $badIPline "from"];		#Ищет в строке2 где начинается 'from'
			:set badIP [:pick $badIPline ($badIPfrom+5) ($badIPfrom+20)];		#Выбор подстроки, исключая 'from ' и 'via' (8.8.8.8 ) (строка3)

			:local position3 [:find $badIP " " 0];		#Ищет в строке3 ' ' (пробел)
			:set badIP1 [:pick $badIP 0 ($position3)];	#Удаляет этот пробел (8.8.8.8)

			:local lIPb1 [:pick $badIP1 0 8];		#192.168.0.0-192.168.255.255
			:local lIPb2 [:pick $badIP1 0 7];		#172.16.0.0-172.31.255.255
			:local lIPb3 [:pick $badIP1 0 3];		#10.0.0.0-10.255.255.255

			:if ($lIPb1 = "192.168." || $lIPb3 = "10." || \ 
			$lIPb2 = "172.16." || $lIPb2 = "172.17." || $lIPb2 = "172.18." || $lIPb2 = "172.19." || \ 
			$lIPb2 = "172.20." || $lIPb2 = "172.21." || $lIPb2 = "172.22." || $lIPb2 = "172.23." || \
			$lIPb2 = "172.24." || $lIPb2 = "172.25." || $lIPb2 = "172.26." || $lIPb2 = "172.27." || \ 
			$lIPb2 = "172.28." || $lIPb2 = "172.29." || $lIPb2 = "172.30." || $lIPb2 = "172.31.")
			do={ :log info "Did you forgot your password\?"; :put "Did you forgot your password\?" }
			else={ /ip firewall address-list add list=$blacklistName address=$badIP1 timeout=$timeout };		#Проверяет локальный ли этот IP

		} on-error={ :log info "AutoBan Script has crashed"; :put "AutoBan Script has crashed" };		#Вывод информации в логи при ошибке
	}
