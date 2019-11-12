#include <iostream>
#include <string>
#include <fstream>
#include <chrono>

#ifndef BYTE
#define BYTE char
#endif

#include "NetworkUtils.h"

using namespace std;
using namespace std::chrono;


enum party_t {SERVER, CLIENT};



int main(int argc, char ** argv){
	string ip_addr = "";
	unsigned int port = 0;
	party_t party;
	for(int argx = 1; argx < argc; argx++){
		if(!strcmp(argv[argx], "-a")){
			ip_addr = argv[++argx];
			continue;
		}
		if(!strcmp(argv[argx], "-p")){
			port = atoi(argv[++argx]);
			continue;
		}
		if(!strcmp(argv[argx],"-w")){
			argx++;
			if(argv[argx][0] == 's'){
				party = SERVER;
			}
			else if(argv[argx][0] == 'c'){
				party = CLIENT;
			}
			else{
				cout << "Unrecognized party argument: " << argv[argx][0] << endl;
				return 0;
			}
			continue;
		}
		cout << "Unrecognized option: " << argv[argx] << endl;
		return 0;
	}
	//Check input
	if(ip_addr == ""){
		cout << "No IP address given!" << endl;
		return 0;
	}
	if(!port){
		cout << "Port invalid or missing!" << endl;
		return 0;
	}


	//Read in address info
	/*
	party_info server_info, client_info;
	fstream addr_fstream(address_file);
	char party_in = 'b';
	string ip_addr = "";
	unsigned int port;
	while(addr_fstream >> party_in >> ip_addr >> port){
		if(!addr_fstream.good()){
			cerr << "Reading from address file failed!" << endl;
			return 1;
		}
		if(party_in == 'c'){
			client_info.type = CLIENT;
			client_info.ip_addr = ip_addr;
			client_info.port = port;
		}
		else if(party_in == 's'){
			server_info.type = SERVER;
			server_info.ip_addr = ip_addr;
			server_info.port = port;
		}
		else{
			cout << "Unrecognized party in address file: " << party << endl;
			return 0;
		}
	}
	*/

	//Read in input/output info
	unsigned int num_messages;
	//Message sizes are in bytes
	vector<unsigned int> message_sizes;
	unsigned int next_msg;
	while(std::cin >> next_msg){
		if(!std::cin.good()){
			cout << "Reading from input failed!" << endl;
			return 0;
		}
		message_sizes.push_back(next_msg);
	}
	num_messages = message_sizes.size();

	high_resolution_clock::time_point start, end;

	//Server
	if(party == SERVER){
		Server box(port);
		if(box.init() || box.accept_connections(1)){
			cerr << "Server initialization failed!" << endl;
			return 1;
		}
		for(unsigned int i = 0; i < num_messages; i++){
			//Send message, get response, and time
			unsigned int message_length = message_sizes[i];
			unsigned int recv_len;
			char * data = new char[message_length];
			char * response;
			//Start timing
			start = high_resolution_clock::now();
			//Recieve message from client
			box.recvString(0, recv_len, &response);
			//Send response back
			box.sendString(0, message_length, data);
			//End timing
			end = high_resolution_clock::now();

			//Find and output message length and time (ns)
			//Clean up memory
			double duration = duration_cast<chrono::nanoseconds>(end-start).count();
			cout << message_length << ' ' << duration << endl;
			delete[] data;
			delete[] response;
		}
		box.stop();
	}
	//Setup client
	else{
		Client box(port, ip_addr.c_str());
		if(box.init()){
			cerr << "Client initialization failed!" << endl;
			return 1;
		}
		for(unsigned int i = 0; i < num_messages; i++){
			//Send message, get response, and time
			unsigned int message_length = message_sizes[i];
			unsigned int recv_len;
			char * data = new char[message_length];
			char * response;
			//Start timing
			start = high_resolution_clock::now();
			//Probably should check return vals here but we are aiming for speed
			//Send message
			box.sendString(message_length, data);
			//Get response
			box.recvString(recv_len, &response);
			//End timing
			end = high_resolution_clock::now();

			//Find and output message length and time (ns)
			//Clean up memory
			double duration = duration_cast<chrono::nanoseconds>(end-start).count();
			cout << message_length << ' ' << duration << endl;
			delete[] data;
			delete[] response;
		}
		box.stop();
	}


	return 0;
}