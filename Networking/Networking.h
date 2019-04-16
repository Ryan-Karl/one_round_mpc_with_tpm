#ifndef SENDANDRECV_H
#define SENDANDRECV_H

#include "NetworkCommon.h"
#include "Client.h"
#include "Server.h"



int broadcast_and_receive(const std::vector<std::string> & hostnames, const std::vector<unsigned int> & ports,
 const std::string & filename, unsigned int port, unsigned int partynum){
	//Error checks
	if(hostnames.size() != ports.size() || hostnames.size() < 2 || partynum >= hostnames.size()){
		std::cerr << "ERROR: hostnames/ports" << std::endl;
		return 1;
	}
	//Start server thread
	int thread_ret = 0;
	std::thread server_thread(&broadcast_file, thread_ret, filename, hostnames.size()-1);
	//Start client threads
	std::thread * client_threads = new std::thread[hostnames.size()];
	int * rets = new int[hostnames.size()];
	for(unsigned int i = 0; i < hostnames.size(); i++){
		if(i == partynum){
			continue;
		}
		client_threads[i] = std::thread(&receive_file, &(rets[i]), hostnames[i], ports[i], i);
	}
	//Join threads

	for(auto & x : client_threads){
		x.join();
	}
	server_thread.join();

	for(const int & r : rets){
		if(r){
			std::cerr << "ERROR returning from client " << std::endl;
			return 1;
		}
	}
	if(thread_ret){
		std::cerr << "ERROR returning from server" << std::endl;
	}
	delete[] client_threads;
	delete[] rets;
	return 0;
}

#endif