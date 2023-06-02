string hexIp(int a, int b, int c, int d) {
	string ip = "";
	ip += (char)a;
	ip += (char)b;
	ip += (char)c;
	ip += (char)d;
	return ip;
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

string encodeMAC(string m) {
	string clean, mac;
	for(int i = 0; i < m.size(); i++) {
		if(m[i] != '-' && m[i] != ':')
			clean += m[i];
	}
	for(int i = 0; i < 6; i++) {
		string n;
		n += m[i*2];
		n += m[i*2+1];
		mac += hex2int(n);
	}
	return mac;
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
	string hex;
	string o = "";
	int n = 0;
	for(int i = 0; i < IP.size(); i++) {
		if(IP[i] != '.') {
			o += IP[i];
		} else {
			hex += octetToHex(o);
			o = "";
			n++;
		}
		if(n == 4) break;
	}
	hex += octetToHex(o);
	return ipAddr(hex);
}

string hexIp2human(string ip) {
	string hIp = "";
	stringstream a;
	for(int i = 0; i < 4; i++)
		a << dec << (int)(unsigned char)ip[i] << (i == 3 ? "" : ".");
	return a.str();
}

string hexMac2human(string mac) {
	string hMac = "";
	stringstream a;
	for(int i = 0; i < 6; i++)
		a << hex << (int)(unsigned char)mac[i] << (i == 5 ? "" : ":");
	return a.str();
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

