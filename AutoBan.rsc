:foreach line in=[/log find buffer=achtung] do= {
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

			/ip firewall address-list add list=blacklist address=$badIP1 timeout=180d;
		} on-error={};
	}