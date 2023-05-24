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

using namespace std;
string myHexIp = "\xc0\xa8\x1\xc8";

int sendSocket;
int lastIp = 100;
sockaddr_in broadcastAddr;

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

class reservation {
	public:
	string mac;
	string ip;
	reservation(string m, string i) {
		mac = m;
		ip = i;
	}
};

struct transaction {
	string id;
	string mac;
	string ip;
};

vector <transaction> transactions;
vector <reservation> reservations;
//\033[0;42m \033[0m

void red(string text) {
	cout <<	"\033[41m" << text << "\033[0m\n";
}

void green(string text) {
	cout <<	"\033[42m" << text << "\033[0m\n";
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


string hexIp(int a, int b, int c, int d) {
	string ip = "";
	ip += (char)a;
	ip += (char)b;
	ip += (char)c;
	ip += (char)d;
	return ip;
}

void hexIp2human(string ip) {
	string hIp = "";
	for(int i = 0; i < 4; i++)
		cout << dec << (int)(unsigned char)ip[i] << ".";
	cout << "\n";
}

string nZeros(int n) {
	string zeros = "";
	for(int i = 0; i < n; i++)
		zeros += '\n';
	return zeros;
}

bool macsEqual(string mac1, string mac2) {
	for(int i = 0; i < 6; i++) {
		if(mac1[i] != mac2[i])
			return false;
	}
	return true;
}

string getFreeIp(string mac) {
	for(int i = 0; i < reservations.size(); i++) {
		if(macsEqual(reservations[i].mac, mac))
			return reservations[i].ip;	
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


string encodeDHCPpack(string xid, string yiaddr, string mac, vector <option> options) {
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
	string messageType;
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
	messageType = findOption(recieved_options, '\x35');
	
	if(cookie == MAGIC_COOKIE) {
		if(messageType == "\x1") { //DISCOVER
			green("Otrzymano DISCOVER");
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
				options.push_back(option('\x36', myHexIp));
				options.push_back(option('\x33', nZeros(2) + "\x02\x58"));
				options.push_back(option('\x1', hexIp(255,255,255,0)));
				options.push_back(option('\x0f', DOMAIN));
				broadcastMessage(encodeDHCPoffer(xid, current_transaction.ip, chaddr, options));
				green("Wysłano DHCPoffer");
			} else
				red(" Ale transakcja już istnieje");
		}

		if(messageType == "\x3") { //REQUEST
			green("Otrzymano REQUEST");
			if(transaction_exists(xid).id == "-1") {
				vector <option> options;
				options.push_back(option('\x36', myHexIp));
				options.push_back(option('\x33', nZeros(2) + "\x02\x58"));
				options.push_back(option('\x1', hexIp(255,255,255,0)));
				options.push_back(option('\x0f', DOMAIN));
				broadcastMessage(encodeDHCPpack(xid, findOption(recieved_options, '\x32'), chaddr, options));
				green("Wysłano DHCPpack, przypisano IP ");
				hexIp2human(findOption(recieved_options, '\x32'));
			} else {
				vector <option> options;
				options.push_back(option('\x36', myHexIp));
				options.push_back(option('\x33', nZeros(2) + "\x02\x58"));
				options.push_back(option('\x1', hexIp(255,255,255,0)));
				options.push_back(option('\x0f', DOMAIN));
				broadcastMessage(encodeDHCPpack(xid, transaction_exists(xid).ip, chaddr, options));
				green("Wysłano DHCPpack, przypisano IP ");
				hexIp2human(transaction_exists(xid).ip);
			}
		}
	}
	return xid;
}
int hexNum(char num) {
	switch(num) {
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'A': return 10;
		case 'B': return 11;
		case 'C': return 12;
		case 'D': return 13;
		case 'E': return 14;
		case 'F': return 15;
	}
	return -1;
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

char octetToHex(string octet) {
	int r = 0;
	int n = 1;
	for(int i = octet.size() - 1; i >= 0; i--) {
		r += ((int)octet[i]-48)*n;
		n *= 10;
	}
	return r;
}

int main() {
	fstream plik;
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
	}
	char broadcastIP[] = "255.255.255.255";
	int broadcastPermission;
	unsigned int sendStringLen;
	if ((sendSocket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		red("socket() failed");
		char netif[] = "enp0s3";
	setsockopt(sendSocket, SOL_SOCKET, SO_BINDTODEVICE, netif, sizeof(netif));
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
