fstream config_file;
	config_file.open("config.txt", ios_base::in);
	if(config_file) {
		int configScope = CONFIG_SCOPE_GLOBAL;
		char line[1024];
		while(config_file.getline(line, 1024)) {
			if(line[0] == '#' || line[0] == '\x0' || line[0] == ' ')
				continue;
			int i;
			vector <string> splitted = splitByChar(line, '=');
			string param = splitted[0];
			string value = splitted[1];

			cout << "Opcja: " << param << "\twartość: " << value << "\n";
			if(param == "range") {
				configScope = CONFIG_SCOPE_RANGE;
				range newRange(value);
				ranges.push_back(newRange);
			}
			if(param == "host") {
				configScope = CONFIG_SCOPE_HOST;
				reservation newReservation(value);
				reservations.push_back(newReservation);
			}
			if(param == "interface")
				interface = value;

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
						eservations[reservations.size()-1].ip.hex = encodeIp(value);
						
				break;
			}
			
			if(param == "routers") {
				vector <ipAddr> routers = splitAddresses(value);
				selectedOption->routers.insert(selectedOption->routers.begin() , routers.begin(), routers.end());
			}
			else if(param == "dns") {
				vector <ipAddr> dns = splitAddresses(value);
				selectedOption->dns.insert(selectedOption->dns.begin() , dns.begin(), dns.end());
			}
			else if(param == "time")
				selectedOption->time = encodeTime(value);
			else if(param == "mask")
				selectedOption->mask = encodeMask(value);

				
		}
		for(int i = 0; i < globalOptions.routers.size(); i++) {
			hex_dump(globalOptions.routers[i].hex);
		}
		hex_dump(ranges[0].options.mask.hex);
	}
