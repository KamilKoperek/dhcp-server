#include <bits/stdc++.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <fstream>
 
#define MAGIC_COOKIE "\x63\x82\x53\x63"
#define DOMAIN "domena123.com.pl"

#define OPTION_NETMASK '\x1'
#define OPTION_MESSAGE_TYPE '\x35'
#define OPTION_DNS '\x6'
#define OPTION_LEASE_TIME '\x33'
#define OPTION_DHCP_IP '\x36'
#define OPTION_DOMAIN_NAME '\x0f'

#define MESSAGE_DISCOVER '\x1'
#define MESSAGE_REQUEST '\x3'
#define MESSAGE_RELEASE '\x7'

using namespace std;
string myHexIp = "\xc0\xa8\x1\xc8";


int sendSocket;
int lastIp = 100;
sockaddr_in broadcastAddr;
string hexIp(int a, int b, int c, int d);


string hexIp2human(string);

class ipAddr {
	public:
		string hex, human;
		bool unset = false;
		ipAddr(string h = "") {
			if(h == "unset")
				unset = true;
			hex = h;
			human = hexIp2human(hex);
		}
		ipAddr(int a, int b, int c, int d) {
			hex = hexIp(a,b,c,d);
			human = hexIp2human(hex);
		}
};
#include "converters.cpp"


class option {
	public:
	char type;
	char length;
	string value;
	option(char t, string v) {
		type = t;
		value = v;
		length = (char)(v.size());
	}
};

string findOption(vector <option> options, char type) {
	for(int i = 0; i < options.size(); i++) {
		if(options[i].type == type)
			return options[i].value;
	}
	return "";
}



class optionsList {
	public:
		ipAddr mask = ipAddr("unset");
		int time = -1;
		vector <ipAddr> routers;
		vector <ipAddr> dns;
		string domain = "";	
};
optionsList globalOptions;
class reservation {
	public:
	string mac;
	ipAddr ip;
	reservation(string m = "") {
		mac = encodeMAC(m);
	}
	optionsList options;
};

class range {
	public:
		ipAddr beginIp;
		ipAddr endIp;
		optionsList options;
		range(string ips) {
			vector <string> splittedIps = splitByChar(ips, '-');
			beginIp = encodeIp(splittedIps[0]);
			endIp = encodeIp(splittedIps[1]);
		}
};

struct transaction {
	string id;
	string mac;
	string ip;
};


void fillOptionList(optionsList* opt) {
	if(opt->mask.unset)
		opt->mask = globalOptions.mask;
	if(opt->time == -1)
		opt->time = globalOptions.time;
	if(opt->domain == "")
		opt->domain = globalOptions.domain;
	if(opt->routers.size() == 0)
		opt->routers = globalOptions.routers;
	if(opt->dns.size() == 0)
		opt->dns = globalOptions.dns;
}



vector <transaction> transactions;
vector <reservation> reservations;
vector <range> ranges;
//\033[0;42m \033[0m

void red(string text) {
	cout << "\033[41m" << text << "\033[0m\n";
}

void green(string text) {
	cout << "\n\033[42m" << text << "\033[0m";
}


void info(string text, ...) {
	bool inverse = false;
	bool underline = false;
	bool bold = false;
	int color = 3;
	va_list arg;
	va_start(arg, text);

	for(int i = 0; i < text.size(); i++) {
		if(text[i] == '%') {
			switch (text[i+1]) {
				case 's': cout << va_arg(arg, string); break;
				case 'c': cout << va_arg(arg, char*); break;
				case 'i': cout << va_arg(arg, int); break;
			}
			i++;
			continue;    		
		} else if(text[i] == '#') {
			cout << "\033[0m";
			switch(text[i+1]) {
				case 'r': color = 0; break;
				case 'g': color = 1; break;
				case 'y': color = 2; break;
				case 'w': color = 3; break;
				case 'i': inverse = !inverse; break;
				case 'u': underline = !underline; break;
				case 'b': bold = !bold; break;
			}
			if(inverse)
				cout << "\033[7m";
			if(underline)
				cout << "\033[4m";
			if(bold)
				cout << "\033[1m";
			switch(color) {
				case 0: cout << "\033[31m"; break;
				case 1: cout << "\033[32m"; break;
				case 2: cout << "\033[33m"; break;
				case 3: cout << "\033[37m"; break;
			}
			
			i++;
			continue;  
		} else			
			cout << text[i];
	}
	cout << "\033[0m";
	va_end(arg);
}



void hex_dump(string text) {
	for(int i = 0; i < text.size(); i++)
		cout << ((i % 2) ? "\033[0m" : "\033[1m") << (((int)(unsigned char)text[i] < 16) ? "0" : "") << hex << (int)(unsigned char)text[i];
	if(text.size() < 16) {
		for(int i = 0; i < 32-text.size()*2; i++)
			cout << " ";
	}
	cout << "\033[0m|   ";

	for(int i = 0; i < text.size(); i++) {
		if(text[i] > 32 && text[i] < 127)
			cout << text[i];
		else
			cout << ".";
	}
		cout << "\n";
}





string nZeros(int n) {
	string zeros = "";
	for(int i = 0; i < n; i++)
		zeros += '\x0';
	return zeros;
}

bool macsEqual(string mac1, string mac2) {
	for(int i = 0; i < 6; i++) {
		if(mac1[i] != mac2[i])
			return false;
	}
	return true;
}

string getFreeIp(string mac = "") {
	for(int i = 0; i < reservations.size(); i++) {
		if(macsEqual(reservations[i].mac, mac))
			return reservations[i].ip.hex;	
	}
	return hexIp(192,168,1,lastIp++);
}

transaction transaction_exists(string id) {
	for(int i = 0; i < transactions.size(); i++) {
		if(transactions[i].id == id)
			return transactions[i];
	}
	transaction notFound;
	notFound.id = "-1";
	return notFound;
}


#include "dhcp_messages.cpp"




ipAddr encodeMask(string mask) {
	if(mask[0] == '/') {
		mask = mask.substr(1, mask.size()-1);
		int intMask = string2int(mask);
		int o[4];
		
		for(int i = 0; i < 4; i++) {
			int m = 128;
			o[i] = 0;
			for(int j = 0; j < 8; j++) {
				if(intMask == 0)
					break;
				intMask--;
				o[i] += m;
				m /= 2;
			}
		}
		return ipAddr(o[0], o[1], o[2], o[3]);
	}
	else
		return encodeIp(mask);
	return ipAddr(0,0,0,0);
}


vector <ipAddr> splitAddresses(string addresses) {
	vector <ipAddr> response;
	vector <string> addrs = splitByChar(addresses, ',');
	for(int i = 0; i < addrs.size(); i++)
		response.push_back(encodeIp(addrs[i]));
	return response;
} 


int encodeTime(string time) {
	int seconds = 0;
	string num;
	for (int i = 0; i < time.size(); i++) {
		if (time[i] == 'h') {
			seconds += string2int(num) * 3600;
			num = "";
		} else if (time[i] == 'm') {
			seconds += string2int(num) * 60;
			num = "";
		} else if (time[i] == 's') {
			seconds += string2int(num);
			num = "";
		}
		else
			num += time[i];
	}
	return seconds;
}

enum configScopes {
	CONFIG_SCOPE_GLOBAL = 0,
	CONFIG_SCOPE_RANGE = 1,
	CONFIG_SCOPE_HOST = 2

};

string interface;

int main() {
	
	#include "load_config.cpp"
	
	info("\n+---Inicjalizacja socketu:\n");
	
	char broadcastIP[] = "255.255.255.255";
	int broadcastPermission;
	unsigned int sendStringLen;
	if ((sendSocket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		info("#r|     socket() failed\n");
	else
		info("|     socket()\n");

	setsockopt(sendSocket, SOL_SOCKET, SO_BINDTODEVICE, interface.data(), interface.size());
	broadcastPermission = 1;
	if (setsockopt(sendSocket, SOL_SOCKET, SO_BROADCAST, (void *) &broadcastPermission, sizeof(broadcastPermission)) < 0)
		info("#r|     setsockopt() failed\n");
	else
		info("|     setsockopt()\n");

	memset(&broadcastAddr, 0, sizeof(broadcastAddr));
	broadcastAddr.sin_family = AF_INET;
	broadcastAddr.sin_addr.s_addr = inet_addr(broadcastIP);
	broadcastAddr.sin_port = htons(68);

	int recvSocket;
	char buffer[1024];
	sockaddr_in servaddr;
	if ( (recvSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		info("#r|     socket creation failed\n");
		exit(EXIT_FAILURE);
	} else
		info("|     Utworzono socket\n");
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(67);
	if ( bind(recvSocket, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) {
		info("#r|     bind failed\n");
		exit(EXIT_FAILURE);
	} else
		info("|     Podłączono interfejs #b%s\n", interface);
	socklen_t len;
  	int n;

	len = sizeof(servaddr);
  	string xid;
  	
  	info("\n+---Uruchamiono serwer DHCP:\n");
  	while (1) {
	  	n = recvfrom(recvSocket, (char*)buffer, 1024, MSG_WAITALL, ( struct sockaddr *) &servaddr, &len);
		buffer[n] = '\0';
		decodeDHCPmessage(buffer);
	}
	return 0;
}
