#ifdef UTILITIES_H
#define UTILITIES_H

#include "stdafx.h"
#include "Samples.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <cstdio>
#include <iostream>
#include <modes.h>
#include <aes.h>
#include "ShamirSecret.h"
#include <vector>
#include <iterator>
#include <cassert>
#include <fstream>


std::vector<std::vector<BYTE> > vectorsFromHexFile(std::ifstream & ifs) {
	std::string line;
	std::vector<std::vector<BYTE> > ret;
	while (getline(ifs, line)) {
		std::istringstream iss(line);
		iss >> std::hex;
		std::vector<BYTE> tmp;
		ret.push_back(tmp);
		int byteIn;
		while (iss >> std::hex >> byteIn) {
			ret[ret.size() - 1].push_back(byteIn & 0xFF);
		}
	}
	return ret;
}

void outputToStream(std::ostream & os, const std::vector<BYTE> & bv) {
	os << std::hex;
	for (size_t i = 0; i < bv.size(); i++) {
		os << (int) bv[i];
		os << " ";
		/*
		if((i%4) == 3){
			os << " ";
		}
		*/
	}
}


std::string ByteVecToString(const std::vector<BYTE> & v) {
	std::string str = "";
	for (const auto & c : v) {
		str += c;
	}
	return str;
}

mpz_class ByteVecToMPZ(const std::vector<BYTE> & v){
	mpz_class mcand = 1;
	mpz_class result = 0;
	for(const auto & c : v){
		result += mcand*c;
		//Shift left by 8 bits
		mpz_mul_2exp(mcand.get_mpz_t(), mcand.get_mpz_t(), 8);
	}
	return result;
}


ByteVec mpz_to_vector(const mpz_t x) {
	size_t size = (mpz_sizeinbase(x, 2) + CHAR_BIT - 1) / CHAR_BIT;
	std::vector<BYTE> v(size);
	mpz_export(&v[0], &size, 1, 1, 0, 0, x);
	v.resize(size);
	return v;
}

inline ByteVec mpz_to_vector(mpz_class & x) {
	return mpz_to_vector(x.get_mpz_t());
}

std::vector<BYTE> intToByteVec(int x) {
	std::vector<BYTE> ret;
	ret.reserve(4);
	ret.push_back((x >> 24) & 0xFF);
	ret.push_back((x >> 16) & 0xFF);
	ret.push_back((x >> 8) & 0xFF);
	ret.push_back(x & 0xFF);
	return ret;
}


#endif