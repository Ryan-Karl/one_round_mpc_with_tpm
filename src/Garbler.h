#include <string>
#include <vector>
#include "Utilities.h"
using std::string;
using std::vector;



class Garbler{

public:
	Garbler(const string & circuit_file, const unsigned long long lambda);
	Garbler() = delete;

	void run(const unsigned int num_parties);

private:

	KeyType getSymmetricKey();
	vector<KeyType> encryptKeyShares();
}