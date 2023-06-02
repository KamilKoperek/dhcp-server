fstream config_file;
config_file.open("config.txt", ios_base::in);
if(config_file) {
	int configScope = CONFIG_SCOPE_GLOBAL;
	char line[1024];
	info("+---Wczytywanie pliku konfiguracyjnego\n");
	int lineNum = 0;
	while(config_file.getline(line, 1024)) {
		lineNum++;
		if(line[0] == '#' || line[0] == '\x0' || line[0] == ' ')
			continue;
		int i;
		vector <string> splitted = splitByChar(line, '=');
		if(splitted.size() < 2) {
			info("#r|#y   Brak wartości opcji w lini #i%i#i: \"#b%c#b\"\n", lineNum, line);
			continue;
		}
		string param = splitted[0];
		string value = splitted[1];
		
		//info("|   %s:  #b\t%s\n", param, value);

		optionsList* selectedOption;
		switch(configScope) {
			case CONFIG_SCOPE_GLOBAL:
				selectedOption = &globalOptions;
			break;
			
			case CONFIG_SCOPE_RANGE:
				selectedOption = &(ranges[ranges.size()-1].options);
			break;
			
			case CONFIG_SCOPE_HOST:
				selectedOption = &(reservations[reservations.size()-1].options);
				if(param == "ip")
					reservations[reservations.size()-1].ip = encodeIp(value);
				
			break;
		}
		
		if(param == "range") {
			configScope = CONFIG_SCOPE_RANGE;
			range newRange(value);
			ranges.push_back(newRange);
			//info("\n+---Zakres\t#g#b%s\n", value);
		} else if(param == "host") {
			configScope = CONFIG_SCOPE_HOST;
			reservation newReservation(value);
			reservations.push_back(newReservation);
			//info("\n+---Host\t#g#b%s\n", value);
		} else if(param == "interface")
			interface = value;
		else if(param == "routers") {
			vector <ipAddr> routers = splitAddresses(value);
			selectedOption->routers.insert(selectedOption->routers.begin() , routers.begin(), routers.end());
		} else if(param == "dns") {
			vector <ipAddr> dns = splitAddresses(value);
			selectedOption->dns.insert(selectedOption->dns.begin() , dns.begin(), dns.end());
		} else if(param == "time")
			selectedOption->time = encodeTime(value);
		else if(param == "mask")
			selectedOption->mask = encodeMask(value);
		else if(param == "domain")
			selectedOption->domain = value;
		else if(param != "ip")
			info("#r|#y   Opcja nie rozpoznana w lini w lini #i%i#i: \"#b%c#b\"\n", lineNum, line);
	}
	
	
	
	for(int j = 0; j < ranges.size(); j++)
		fillOptionList(&ranges[j].options);
	for(int j = 0; j < reservations.size(); j++)
		fillOptionList(&reservations[j].options);
	
	if(interface == "")
		info("#rBrak wybranego interfejsu");

	
	info("\n+---Globalne:\n");
	info("|     Maska podsieci:#b\t%s\n", globalOptions.mask.human);
	info("|     Czas dzierżawy:#b\t%is\n", globalOptions.time);
	info("|     Domena:#b\t%s\n", globalOptions.domain);
	info("|     Routery:\t");
	for(int i = 0; i < globalOptions.routers.size(); i++)
		info("#b%s#b%c", globalOptions.routers[i].human, ((i == globalOptions.routers.size() -1 ? " " : ", ")));
	info("\n|     DNSy:\t");
	for(int i = 0; i < globalOptions.dns.size(); i++)
		info("#b%s#b%c", globalOptions.dns[i].human, ((i == globalOptions.dns.size() -1 ? " " : ", ")));
		
	for(int j = 0; j < ranges.size(); j++) {
		info("\n\n+---Zakres #g%s-%s\n", ranges[j].beginIp.human, ranges[j].endIp.human);
		info("|     Maska podsieci:#b\t%s\n", ranges[j].options.mask.human);
		info("|     Czas dzierżawy:#b\t%is\n", ranges[j].options.time);
		info("|     Domena:#b\t%s\n", ranges[j].options.domain);
		info("|     Routery:\t");
		for(int i = 0; i < ranges[j].options.routers.size(); i++)
			info("#b%s#b%c", ranges[j].options.routers[i].human, ((i == ranges[j].options.routers.size() -1 ? " " : ", ")));
		info("\n|     DNSy:\t");
		for(int i = 0; i < ranges[j].options.dns.size(); i++)
			info("#b%s#b%c", ranges[j].options.dns[i].human, ((i == ranges[j].options.dns.size() -1 ? " " : ", ")));
	}
	
	for(int j = 0; j < reservations.size(); j++) {
		info("\n\n+---Rezerwacja #gMAC: %s IP: %s\n", hexMac2human(reservations[j].mac), reservations[j].ip.human);
		info("|     Maska podsieci:#b\t%s\n", reservations[j].options.mask.human);
		info("|     Czas dzierżawy:#b\t%is\n", reservations[j].options.time);
		info("|     Domena:#b\t%s\n", reservations[j].options.domain);
		info("|     Routery:\t");
		for(int i = 0; i < reservations[j].options.routers.size(); i++)
			info("#b%s#b%c", reservations[j].options.routers[i].human, ((i == reservations[j].options.routers.size() -1 ? " " : ", ")));
		info("\n|     DNSy:\t");
		for(int i = 0; i < reservations[j].options.dns.size(); i++)
			info("#b%s#b%c", reservations[j].options.dns[i].human, ((i == reservations[j].options.dns.size() -1 ? " " : ", ")));
	}
	
	

	
} else
	info("#r#bProblem z odczytem pliku konfiguracyjnego");
cout << "\n";
