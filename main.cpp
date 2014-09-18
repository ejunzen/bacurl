#include <iostream>
#include <fstream> 
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "base64.h"
#include "hmac.h"
#include "sha1.h"
#include "sha256.h"

#include <time.h>

using namespace std;
using namespace cryptlite;

static string username = "hotel";
static string secret = "bc58e2c15abd49b23f902a4d6a324ca2";

string genorate_sig();

string genorate_sig(int isGet,string url,string date){
	if(isGet>0){
		return "GET " + url + "\n" + date;
	}else{
		return "POST " + url + "\n" + date;
	}
}

char* parseUrl(char* url){
	int hasHttp = 0;
	int index=0;
	int len = strlen(url);
	//step1 find http
	char* start = strstr(url,"http://");
	if(start != NULL&&start == url){
		hasHttp = strlen("http://");
	}
	index = hasHttp;
	while(index < len){
		if(url[index] == '/'){
			break;
		}
		index++;
	}
	char* host = (char*)malloc(index);
	char* queryString = NULL;
	memcpy(host,url+hasHttp,index-hasHttp);
	if(index<len){
		queryString = (char*)malloc(len -index +1);
		memset(queryString,0,len-index+1);
		memcpy(queryString,url+index,len-index);
	}
	return queryString;
}

void readConf(){
	ifstream in("/etc/bacurl.conf",ios::in);
	string line;
	if(in){
		while(getline(in,line)){
			int len = line.length();
			int index = line.find_first_of("username=");
			if(index >= 0){
				username= line.substr(9,len);
				//cout << username << endl;
				continue;
			}
			index = line.find_first_of("secret=");
			if(index >= 0){
				secret= line.substr(7,len);
				//cout << secret << endl;
				continue;
			}
		}
	}
}


int main(int argc, char* argv[]){

	readConf();
	int isGet = 1;

	for(int i=1;i<argc;i++){
		if(strcmp(argv[i],"-d")==0){
			isGet=0;
		}
	}

	time_t timep;
	time(&timep); 
	struct tm *local;
	local = gmtime(&timep);	
	char tmp[1024]; 
	strftime( tmp, sizeof(tmp), "%a, %d %b %Y %X GMT",local); 
	string date = string(tmp);
	string url = string(argv[argc - 1]);

	char* query = parseUrl((char*)url.c_str());

	if(query == NULL){
		query = "";
	}

	string sig = genorate_sig(isGet,string(query),date);

	//cout << sig << endl;

	boost::uint8_t hmacsha1digest[sha1::HASH_SIZE];
	hmac<sha1>::calc(sig, secret, hmacsha1digest);

	std::string sha1base64 = base64::encode_from_array(hmacsha1digest,sha1::HASH_SIZE);

	string cmd = "curl -H\"Date:"+date+"\" -H\"Authorization:MWS "+username+":"+sha1base64+"\" ";
	for(int i=1;i<argc;i++){
		cmd += string(argv[i]);
	    cmd += " ";
	}
	//cout << cmd << endl;

	return system(cmd.c_str());
}
