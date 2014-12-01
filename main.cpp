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

#define DEBUG 0

using namespace std;
using namespace cryptlite;

static string username = "hotel-biz";
static string secret = "b0966084617060081c33e04726ab281c";

static int hasUrl = 0;

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

	//step2 find ?
	int end = index;
	while(end < len){
		if(url[end] == '?'){
			break;
		}
		end++;
	}		

	char* host = (char*)malloc(index);
	char* queryString = NULL;
	memcpy(host,url+hasHttp,index-hasHttp);
	if(index<len){
		queryString = (char*)malloc(len -index +1);
		memset(queryString,0,len-index+1);
		memcpy(queryString,url+index,len-index-(len-end));
	}
#ifdef DEBUG
	cout << queryString << endl;
#endif
	return queryString;
}

void readConf(){
	ifstream in("/etc/bacurl.conf",ios::in);
	string line;
	if(in){
		while(getline(in,line)){
			int len = line.length();
			int index = line.find_first_of("sername=");
			if(index > 0){
				username= line.substr(9,len);
#ifdef DEBUG
				cout << username << endl;
#endif
				continue;
			}
			index = line.find_first_of("ecret=");
			if(index > 0){
				secret= line.substr(7,len);
#ifdef DEBUG
				cout << secret << endl;
#endif
				continue;
			}
		}
	}
}


int main(int argc, char* argv[]){

	readConf();
	int isGet = 1;

	for(int i=1;i<argc;i++){
		if(strstr(argv[i],"-d") != NULL){
			isGet=0;
		}
		if(strstr(argv[i],"-X")!= NULL && i+1 < argc && strstr(argv[i+1],"POST")!=NULL){
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

#ifdef DEBUG
	cout << sig << endl;
#endif
	boost::uint8_t hmacsha1digest[sha1::HASH_SIZE];
	hmac<sha1>::calc(sig, secret, hmacsha1digest);

#ifdef DEBUG
	cout << hmacsha1digest << endl;
#endif
	std::string sha1base64 = base64::encode_from_array(hmacsha1digest,sha1::HASH_SIZE);

#ifdef DEBUG
	cout << sha1base64 << endl;
#endif

	string cmd = "curl -H\"Date:"+date+"\" -H\"Authorization:MWS "+username+":"+sha1base64+"\" ";
	for(int i=1;i<argc;i++){

		if(strstr(argv[i],"-d")!=NULL
				&& strcmp(argv[i],"-d")!= 0){

			string temp = string(argv[i]);
			int len = strlen(argv[i]);
			cmd += "-d\"";
			cmd += temp.substr(2);
			cmd += "\" ";
			continue;
		}

		if(strstr(argv[i],"http://")!=NULL
				|| strstr(argv[i],"www")!=NULL
				|| (i==argc-1 && hasUrl==0)){
			cmd += "--url ";
			hasUrl = 1;
		}
		cmd += string(argv[i]);
		cmd += " ";
	}
#ifdef DEBUG
	cout << cmd << endl;
#endif	

	//return 0;
	return system(cmd.c_str());
}
