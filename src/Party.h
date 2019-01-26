#include <string>
#include <vector>
#include <utility>
#include "Utilities.h"
using std::string;
using std::vector;
using std::pair;


class Party{
public:
	Party();
	//Connect to server, and get info on other parties
	int connectToGarbler(const char * hostname, const unsigned int port, const unsigned int my_id);
	int runProtocol(const vector<bool> & inputs);
private:
	//Initialize
	pair<KeyType, KeyType> getKeyPair();
	char * encryptInputs(const KeyType & publicKey, const vector<bool> & inputs);
	int broadcastPublicKey();
	//Preprocess
	int pubKeyDecrypt(const KeyType & secretKey);
	KeyType combineShares(const vector<KeyType> & shares);
	int symmetricKeyDecrypt(const KeyType & symmKey);
	//Online
	int broadcastWireLabels(const vector<bool> & inputs);
	//Evaluate
	int evaluateCircuit();


}