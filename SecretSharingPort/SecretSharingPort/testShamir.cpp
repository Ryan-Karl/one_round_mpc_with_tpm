#include <iostream>
#include <vector>
#include <string>
#include "ShamirSecret.h"

//Compile with $ g++ testShamir.cpp -o testShamir -std=c++11 -lgmp -lgmpxx

using namespace std;

int main(int argc, char ** argv){

	mpz_class prime = 7919;
	unsigned int shares = 6;
	unsigned int recover = 3;

	ShamirSecret secretSplit(prime, shares, recover);
	//Secret must be in Z_p
	const char * secret = "1993";

	vector<pair<mpz_class, mpz_class> > sharesVec = secretSplit.getShares(secret);

	vector<pair<mpz_class, mpz_class> > firstHalf(sharesVec.begin(), sharesVec.begin() + recover);
	vector<pair<mpz_class, mpz_class> > secondHalf(sharesVec.begin() + recover, sharesVec.end());

	/*
	string firstResult(secretSplit.getSecretString(firstHalf));
	string secondResult(secretSplit.getSecretString(secondHalf));
	*/

	mpz_class first_mpz = secretSplit.getSecret(firstHalf);
	mpz_class second_mpz = secretSplit.getSecret(secondHalf);

	cout << "First result recovered: \t" << first_mpz << endl;
	cout << "Second result recovered: \t" << second_mpz << endl;

	return 0;
}