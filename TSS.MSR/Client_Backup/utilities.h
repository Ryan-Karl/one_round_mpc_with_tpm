#ifndef UTILITIES_H
#define UTILITIES_H


//#include "stdafx.h"
//#include "Samples.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <cstdio>
#include <iostream>
#include <sstream>
//#include <modes.h>
//#include <aes.h>
//#include "ShamirSecret.h"
#include <vector>
#include <iterator>
#include <cassert>
#include <fstream>
#include <limits.h>

#ifdef WIN32
#include <mpir.h>
#include <mpirxx.h>
#elif defined(__linux__)
#include <gmp.h>
#include <gmpxx.h>
typedef unsigned char BYTE;
#endif

#define AES_KEY_SIZE 32
#define IV_SIZE 16


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
		os << (int)bv[i];
		os << " ";
		/*
		if((i%4) == 3){
			os << " ";
		}
		*/
	}
}

std::vector<BYTE> flatten(const std::vector<std::vector<BYTE> > & arr) {
	std::vector<BYTE> ret;
	for (const auto & vec : arr) {
		ret.insert(ret.end(), vec.begin(), vec.end());
	}
	return ret;
}

/*
std::string ByteVecToString(const std::vector<BYTE> & v) {
	std::string str = "";
	for (const auto & c : v) {
		str += c;
	}
	return str;
}
*/

std::vector<BYTE> stringToByteVec(const char * str, unsigned int strlen) {
	std::vector<BYTE> v;
	v.reserve(strlen);
	for (unsigned int i = 0; i < strlen; i++) {
		v.push_back(str[i]);
	}
	return v;
}

std::vector<BYTE> stringToByteVec(const std::string & s) {
	std::vector<BYTE> v;
	v.reserve(s.size());
	for (unsigned int i = 0; i < s.size(); i++) {
		v.push_back(s[i]);
	}
	return v;
}

std::string ByteVecToString(const std::vector<BYTE> & v) {
	std::string str(v.begin(), v.end());
	return str;
}

mpz_class ByteVecToMPZ(const std::vector<BYTE> & v) {
	mpz_class mcand = 1;
	mpz_class result = 0;
	for (const auto & c : v) {
		result += mcand * c;
		//Shift left by 8 bits
		mpz_mul_2exp(mcand.get_mpz_t(), mcand.get_mpz_t(), 8);
	}
	return result;
}



std::vector<BYTE> mpz_to_vector(const mpz_t x) {
	size_t size = (mpz_sizeinbase(x, 2) + CHAR_BIT - 1) / CHAR_BIT;
	std::vector<BYTE> v(size);
	mpz_export(&v[0], &size, 1, 1, 0, 0, x);
	v.resize(size);
	return v;
}

inline std::vector<BYTE> mpz_to_vector(mpz_class & x) {
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

#ifndef CHAR_WIDTH
#define CHAR_WIDTH 8
#endif

std::vector<BYTE> concatenate(const std::vector<BYTE> & v1, const std::vector<BYTE> & v2) {
	unsigned int len = v1.size();
	std::vector<BYTE> v(sizeof(unsigned int));
	v.reserve(sizeof(unsigned int) + len + v2.size());
	for (unsigned int i = 0; i < sizeof(unsigned int); i++) {
		v[i] = (len >> (i*CHAR_WIDTH)) & 0xF;
	}
	v.insert(v.end(), v1.begin(), v1.end());
	v.insert(v.end(), v2.begin(), v2.end());
	return v;
}

int splitIntermediate(const std::vector<BYTE> & v, std::vector<BYTE> & first, std::vector<BYTE> & second) {
	if (v.size() < 5) {
		throw std::logic_error("Vector to split not long enough!");
		return 1;
	}

	unsigned int len = v[0] |
		(v[1] << CHAR_WIDTH) |
		(v[2] << (2 * CHAR_WIDTH)) |
		(v[3] << (2 * CHAR_WIDTH));
	first.clear();
	first.resize(len);
	second.clear();
	second.resize(v.size() - len - sizeof(unsigned int));
	unsigned int i;
	for (i = sizeof(unsigned int); i < v.size(); i++) {
		if (i < sizeof(unsigned int) + len) {
			first[i] = v[i];
		}
		else {
			second[i] = v[i];
		}

	}
	return 0;
}


#endif