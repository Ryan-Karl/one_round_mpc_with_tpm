#ifndef XOR_SHARING
#define XOR_SHARING

#include <vector>
#include <cstdlib>
#include <exception>

using std::vector;

void fill_vector_rand(std::vector<unsigned char> & v){
	for(size_t i = 0; i < v.size(); i++){
		v[i] = (unsigned char) rand();
	}
}

void vector_xor(std::vector<unsigned char> & left, const std::vector<unsigned char> & right){
	if(left.size() != right.size()){
		throw std::logic_error("Invalid sizes");
	}
	for(size_t i = 0; i < left.size(); i++){
		left[i] ^= right[i];
	}
}

std::vector<std::vector<unsigned char> > get_shares(unsigned int num_shares, const std::vector<unsigned char> & secret){
	if(num_shares < 2){
		throw std::logic_error("Not enough shares!");
	}
	std::vector<std::vector<unsigned char> > ret;
	ret.resize(num_shares);
	for(size_t i = 0; i < num_shares - 1; i++){
		ret[i].resize(secret.size());
		fill_vector_rand(ret[i]);
		if(!i){
			ret[ret.size()-1] = ret[0];
		}
		else{
			vector_xor(ret[ret.size()-1], ret[i]);
		}
	}
	vector_xor(ret[ret.size()-1], secret);
	return ret;
}

std::vector<unsigned char> recover_secret(const std::vector<std::vector<unsigned char> > & shares){
	if(shares.size() < 2){
		throw std::logic_error("Not enough shares to reconstruct!");
	}
	std::vector<unsigned char> ret = shares[0];
	for(size_t i = 1; i < shares.size(); i++){
		vector_xor(ret, shares[i]);
	}
	return ret;
}



#endif