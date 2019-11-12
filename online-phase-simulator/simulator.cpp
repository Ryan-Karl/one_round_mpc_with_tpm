#include <iostream>
#include <string>
#include <fstream>
#include <chrono>

#include "NetworkUtils.h"

using namespace std;
using namespace std::chrono;


enum party_t {SERVER, CLIENT};

typedef struct{
	string ip_addr = "";
	unsigned int port = 0;
	party_t type;
} party_info;

int main(int argc, char ** argv){
	string address_file = "";
	string input_file = "";
	char party = 'b';
	for(int argx = 0; argx < argc, argx++){
		if(!strcmp(argv[argx], "-a")){
			address_file = argv[++argx];
			break;
		}
		if(!strcmp(argv[argx], "-i")){
			input_file = argv[++argx];
			break;
		}
		if(!strcmp(argv[argx],"-p")){
			if(argv[++argx][0] == 's'){
				party = SERVER;
			}
			else if(argv[++argx][0] == 'c'){
				party = CLIENT;
			}
			else{
				cout << "Unrecognized party argument: " << argv[++argx][0] << endl;
				return 0;
			}
			break;
		}
	}
	//Check input
	if(address_file == ""){
		cout << "No address file given!" << endl;
		return 0;
	}
	if(input_file == ""){
		cout << "No input file given!" << endl;
		return 0;
	}


	//Read in address info
	party_info server_info, client_info;
	fstream addr_fstream(address_file);
	char party = 'b';
	string ip_addr = "";
	unsigned int port;
	while(addr_fstream >> party >> ip_addr >> port){
		if(!addr_fstream.good()){
			cerr << "Reading from address file failed!" << endl;
			return 1;
		}
		if(party == 'c'){
			client_info.party = CLIENT;
			client_info.ip_addr = ip_addr;
			client_info.port = port;
		}
		else if(party == 's'){
			server_info.party = SERVER;
			server_info.ip_addr = ip_addr;
			server_info.port = port;
		}
		else{
			cout << "Unrecognized party in address file: " << party << endl;
			return 0;
		}
	}
	//Read in input/output info
	unsigned int num_messages;
	//Message sizes are in bytes
	vector<unsigned int> message_sizes;
	fstream msg_fstream(input_file);
	unsigned int next_msg;
	while(msg_fstream >> next_msg){
		if(!msg_fstream.good()){
			cerr << "Reading from input file failed!" << endl;
			return 1;
		}
		message_sizes.push_back(next_msg);
	}
	num_messages = message_sizes.size();


	//Setup networking
	NetworkNode * box;
	if(party == 's'){
		box = new Server(server_info.port);
	}
	//Setup client
	else{
		box = new Client(server_info.port, server_info.ip_addr);
	}
	box->init();

	high::resolution::clock::time_point start, end;
	for(unsigned int i = 0; i < num_messages; i++){
		//Send message, get response, and time
		register unsigned int message_length = message_sizes[i];
		char * data = new char[message_length];
		char * response;

		if(party == CLIENT){
			//Start timing
			start = high_resolution_clock::now();
			//Send message
			box->sendString(message_length, data);
			//Get response
			box->recvString(message_length, &response);
			//End timing
			end = high_resolution_clock::now();
		}
		else{
			//Start timing
			start = high_resolution_clock::now();
			//Recieve message from client
			box->recvString(message_length, &response);
			//Send response back
			box->sendString(message_length, data);
			//End timing
			end = high_resolution_clock::now();
		}
		//Find and output message length and time (ns)
		//Clean up memory
		double duration = duration_cast<chrono::nanoseconds>(end-start).count();
		cout << message_length << ' ' << duration << endl;
		delete data;
		delete response;
	}
	box->stop();
	return 0;
}