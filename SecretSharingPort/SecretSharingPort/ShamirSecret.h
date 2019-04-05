#include "pch.h"
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>
#include <random>
#include <utility>
#include <array>
#include <set>


#ifdef __linux__
#include <gmp.h>
#include <gmpxx.h>
#elif defined(WIN32)
#include <mpir.h>
#include <mpirxx.h>
#else
#error No OS defined!
#endif

using std::pair;
using std::vector;
using std::cout;
using std::endl;

class ShamirSecret{

private:
  mpz_class prime;
  //char * secret;
  unsigned int num_shares;
  unsigned int min_shares_to_recover;

  static bool hasDuplicates(const vector<pair<mpz_class, mpz_class> > & shares) const ;
  mpz_class eval_at(const vector<mpz_class> & poly, const mpz_class & x) const ;
  mpz_class divmod(const mpz_class & num, const mpz_class & den) const ;

public:
  ShamirSecret(mpz_class pr, unsigned int shares, unsigned int recover): prime(pr), num_shares(shares), min_shares_to_recover(recover) {}

  vector<pair<mpz_class, mpz_class> > getShares(const char * secret) const ;
  vector<pair<mpz_class, mpz_class> > getShares(const mpz_class & secret)const ;

  mpz_class getSecret(const vector<pair<mpz_class, mpz_class> > & shares) const ;
  const char * getSecret(const vector<pair<mpz_class, mpz_class> > & shares) const ;
  


}
