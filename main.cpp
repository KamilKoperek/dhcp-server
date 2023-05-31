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

string hexIp(int a, int b, int c, int d) {
	string ip = "";
	ip += (char)a;
	ip += (char)b;
	ip += (char)c;
	ip += (char)d;
	return ip;
}

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

class ipAddr {
	public:
		string hex;
		ipAddr(string h = "") {
			hex = h;
		}
		ipAddr(int a, int b, int c, int d) {
			hex = hexIp(a,b,c,d);
		}
};



class optionsList {
	public:
		ipAddr mask;
		int time;
		vector <ipAddr> routers;
		vector <ipAddr> dns;
		
};

class reservation {
	public:
	string mac;
	ipAddr ip;
	reservation(string m = "") {
		mac = m;
	}
	optionsList options;
	
};
char octetToHex(string octet) {
	int r = 0;
	int n = 1;
	for(int i = octet.size() - 1; i >= 0; i--) {
		r += ((int)octet[i]-48)*n;
		n *= 10;
	}
	return r;
}
vector <string> splitByChar(string s, char c) {
	vector <string> strings;
	strings.push_back("");
	for(int i = 0; i < s.size(); i++) {
		if(s[i] == c) {
			strings.push_back("");
			i++;
		}
		strings[strings.size()-1] += s[i];
	}
	return strings;
}
ipAddr encodeIp(string IP) {
	ipAddr r;
	string o = "";
	int n = 0;
	for(int i = 0; i < IP.size(); i++) {
		if(IP[i] != '.') {
			o += IP[i];
		} else {
			r.hex += octetToHex(o);
			o = "";
			n++;
		}
		if(n == 4) break;
	}
	r.hex += octetToHex(o);
	return r;
}
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



void hexIp2human(string ip) {
	string hIp = "";
	for(int i = 0; i < 4; i++)
		cout << dec << (int)(unsigned char)ip[i] << ".";
	//cout << "\n";
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
int hexNum(char num) {
	if(num >= 48 && num < 58)
		return num - 48;
	else
		return num - 55;
}
int hex2int(string hex) {
	int r = 0;
	int n = 1;
	for(int i = hex.size() - 1; i >= 0; i--) {
		r += hexNum(hex[i]) * n;
		n *= 16;
	}
	return r;
}



int string2int (string s) {
	int n = 0;
	int m = 1;
	for(int i = s.size()-1; i >= 0; i--) {
		n += ((int)s[i]-48)*m;
		m *= 10;
	}
	return n;
}

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

	//hex_dump(encodeIp("16.17.255.16"));

	optionsList globalOptions;
	#include "load_config.cpp"
	/*fstream plik;
	plik.open("rezerwacje.txt", ios_base::in);
	if (!plik) {
		plik.open("rezerwacje.txt",  ios_base::in | ios_base::out | ios_base::trunc);
		plik <<"\n";
		plik.close();
	} else {
		char line[1024];
		green("Wczytano rezerwacje: ");
		while(plik.getline(line, 1024)) {
			cout << line << "\n";
			string mac = "";
			for(int i = 0; i < 6; i++) {
				string n = "";
				n += line[i*2];
				n += line[i*2+1];
				mac += hex2int(n);
			}
			string ip = "";
			string o = "";
			int n = 0;
			for(int i = 13; i < 32; i++) {
				if(line[i] != '.' && line[i] != ' ' && line[i] != '\x0') {
					o += line[i];
				} else {
					ip += octetToHex(o);
					o = "";
					n++;
				}
				if(n == 4) break;
			}
			reservations.push_back(reservation(mac, ip));
		}
	}*/
	char broadcastIP[] = "255.255.255.255";
	int broadcastPermission;
	unsigned int sendStringLen;
	if ((sendSocket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		red("socket() failed");

	setsockopt(sendSocket, SOL_SOCKET, SO_BINDTODEVICE, interface.data(), interface.size());
	broadcastPermission = 1;
	if (setsockopt(sendSocket, SOL_SOCKET, SO_BROADCAST, (void *) &broadcastPermission, sizeof(broadcastPermission)) < 0)
		red("setsockopt() failed");

	memset(&broadcastAddr, 0, sizeof(broadcastAddr));
	broadcastAddr.sin_family = AF_INET;
	broadcastAddr.sin_addr.s_addr = inet_addr(broadcastIP);
	broadcastAddr.sin_port = htons(68);

	int recvSocket;
	char buffer[1024];
	sockaddr_in servaddr;
	if ( (recvSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(67);
	if ( bind(recvSocket, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	socklen_t len;
  	int n;

	len = sizeof(servaddr);
  	string xid;
  	while (1) {
	  	n = recvfrom(recvSocket, (char*)buffer, 1024, MSG_WAITALL, ( struct sockaddr *) &servaddr, &len);
		buffer[n] = '\0';
		//cout << cliaddr.sin_addr.s_addr << "\n\n";
		decodeDHCPmessage(buffer);
	}
	return 0;
}
