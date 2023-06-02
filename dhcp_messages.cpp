string encodeDHCPmessage(string xid, string ciaddr, string yiaddr, string siaddr, string giaddr, string chaddr, vector <option> options) {
	string message = "";
	message += '\x2'; //op
	message += '\x1'; //htype
	message += '\x6'; //hlen
	message += '\x0'; //hops

	message += xid;

	message += nZeros(2); //secs
	message += nZeros(2); //flags

	message += ciaddr;
	message += yiaddr;
	message += siaddr;
	message += giaddr;

	message += chaddr;

	message += nZeros(64); //sname

	message += nZeros(128); //file

	//options:

	message += MAGIC_COOKIE;

	for(int i = 0; i < options.size(); i++) {
		message += options[i].type;
		message += options[i].value.size();
		message += options[i].value;
	}

	message += '\xff';
	//message += nZeros(31);
	return message;
}

string encodeDHCPoffer(string xid, string yiaddr, string mac, vector <option> options) {
	options.push_back(option('\x35', "\x2"));
	return encodeDHCPmessage(xid, nZeros(4), yiaddr, myHexIp, nZeros(4), mac, options);
}


string encodeDHCPack(string xid, string yiaddr, string mac, vector <option> options) {
	options.push_back(option('\x35', "\x5"));
	return encodeDHCPmessage(xid, nZeros(4), yiaddr, myHexIp, nZeros(4),  mac, options);
}

void broadcastMessage(string text) {
	sendto(sendSocket, text.data(), text.size(), 0, (struct sockaddr *) &broadcastAddr, sizeof(broadcastAddr));
}


string decodeDHCPmessage(char *buffer) {
	char op = buffer[0];
	char htype = buffer[1];
	char hlen = buffer[2];
	char hops = buffer[3];

	string xid = "";
	for(int i = 4; i < 8; i++)
		xid+=buffer[i];

	string secs = "";
	for(int i = 8; i < 10; i++)
		secs+=buffer[i];

	string flags = "";
	for(int i = 10; i < 12; i++)
		flags+=buffer[i];

	string ciaddr = "";
	for(int i = 12; i < 16; i++)
		ciaddr+=buffer[i];

	string yiaddr = "";
	for(int i = 16; i < 20; i++)
		yiaddr+=buffer[i];

	string siaddr = "";
	for(int i = 20; i < 24; i++)
		siaddr+=buffer[i];

	string giaddr = "";
	for(int i = 24; i < 28; i++)
		giaddr+=buffer[i];

	string chaddr = "";
	for(int i = 28; i < 44; i++)
		chaddr+=buffer[i];

	string sname = "";
	for(int i = 44; i < 108; i++)
		sname+=buffer[i];

	string file = "";
	for(int i = 108; i < 236; i++)
		file+=buffer[i];

	string cookie = "";
	for(int i = 236; i < 240; i++)
		cookie+=buffer[i];

	int i = 240;

	vector <option> recieved_options;
	char messageType;
	while(buffer[i] != '\xff') {
		option current_option('\x0', "\x0");
		current_option.type = buffer[i++];
		int l = (int)buffer[i];
		current_option.value = "";
		for(int j = 0; j < l; j++)
			current_option.value += buffer[i+j+1];
		i += l+1;
		recieved_options.push_back(current_option);
	}
	messageType = findOption(recieved_options, '\x35')[0];
	
	if(cookie == MAGIC_COOKIE) {
		switch (messageType) {
			case MESSAGE_DISCOVER:
				green("Otrzymano DISCOVER od " + findOption(recieved_options, '\xc'));
				if(transaction_exists(xid).id == "-1") {
					transaction current_transaction;
					current_transaction.id = xid;
					current_transaction.mac = chaddr;
					current_transaction.ip = getFreeIp(chaddr);
					transactions.push_back(current_transaction);
					cout << "\nZarejestrowano nową transakcje o xid:\n";
					hex_dump(xid);
					cout << "\nMAC:\n";
					hex_dump(chaddr);
					cout << "\nIP:\n";
					hexIp2human(current_transaction.ip);

					vector <option> options;
					options.push_back(option(OPTION_DHCP_IP, myHexIp));
					options.push_back(option(OPTION_DNS, hexIp(8,8,8,8)+hexIp(1,1,1,1)));
					options.push_back(option(OPTION_LEASE_TIME, nZeros(2) + "\x02\x58"));
					options.push_back(option(OPTION_NETMASK, hexIp(255,255,255,0)));
					options.push_back(option(OPTION_DOMAIN_NAME, DOMAIN));
					broadcastMessage(encodeDHCPoffer(xid, current_transaction.ip, chaddr, options));
					green("Wysłano DHCPoffer");
				} else {
					red(" Ale transakcja już istnieje");
					vector <option> options;
					options.push_back(option(OPTION_DHCP_IP, myHexIp));
					options.push_back(option(OPTION_DNS, hexIp(8,8,8,8)+hexIp(1,1,1,1)));
					options.push_back(option(OPTION_LEASE_TIME, nZeros(2) + "\x02\x58"));
					options.push_back(option(OPTION_NETMASK, hexIp(255,255,255,0)));
					options.push_back(option(OPTION_DOMAIN_NAME, DOMAIN));
					broadcastMessage(encodeDHCPoffer(xid, transaction_exists(xid).ip, chaddr, options));
				}
			break;
			case MESSAGE_RELEASE:
				green("Otrzymano RELEASE od " + findOption(recieved_options, '\xc'));
			break;
			case MESSAGE_REQUEST:
				green("Otrzymano REQUEST od " + findOption(recieved_options, '\xc'));
				string ip;
				if(transaction_exists(xid).id == "-1")
					ip = findOption(recieved_options, '\x32');			
				else
					ip =transaction_exists(xid).ip;
				
				vector <option> options;
				options.push_back(option(OPTION_DHCP_IP, myHexIp));
				options.push_back(option(OPTION_DNS, hexIp(8,8,8,8)+hexIp(1,1,1,1)));
				options.push_back(option(OPTION_LEASE_TIME, nZeros(2) + "\x02\x58"));
				options.push_back(option(OPTION_NETMASK, hexIp(255,255,255,0)));
				options.push_back(option(OPTION_DOMAIN_NAME, DOMAIN));
				if(ip[0] == '\x0')
					ip = getFreeIp();
				broadcastMessage(encodeDHCPack(xid, ip, chaddr, options));
				green("Wysłano DHCack, przypisano IP ");
				hexIp2human(ip);
				cout << "\n";
			break;
		}
		
	}
	return xid;
}
