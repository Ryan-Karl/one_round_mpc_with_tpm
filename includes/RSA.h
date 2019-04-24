#ifndef RSA_H
#define RSA_H

//(Some) Inspiration from Adam Brockett
//https://github.com/gilgad13/rsa-gmp/blob/master/rsa.c

//Remember to compile with -lgmp and -lgmpxx

#include <stdlib.h>
#include <string>
#include <sstream>

#ifdef WIN32
#include <mpir.h>
#include <mpirxx.h>
#elif defined(__linux__)
#include <gmp.h>
#include <gmpxx.h>
#endif

typedef struct {
  mpz_class n; //Modulus
  mpz_class e; //Public exponent
} public_key;

typedef struct {
  public_key pk; //Pub. key contains modulus and exponent
  mpz_class d; //Private exponent
  mpz_class p; //Primes p and q
  mpz_class q;
} private_key;

void gen_keys(private_key & priv, unsigned int num_bits){
  //Set randomness - not cryptographically secure!
  //TODO find a better way
  srand(time(NULL));
  //Create random strings of bits and assign p and q
  std::string pstr = "";
  std::string qstr = "";
  for(unsigned int i = 0; i < num_bits; i++){
    pstr += (rand()%2)? '0' : '1';
    qstr += (rand()%2)? '0' : '1';
  }
  priv.p = pstr;
  priv.q = qstr;
  //Force p and q to be prime
  mpz_nextprime(priv.p.get_mpz_t(), priv.p.get_mpz_t());
  mpz_nextprime(priv.q.get_mpz_t(), priv.q.get_mpz_t());
  //Assign n
  priv.pk.n = priv.p*priv.q;
  //Calculate totient of n
  mpz_class phi = (priv.p-1)*(priv.q-1);
  //Choose e - up to totient at most.
  gmp_randstate_t randstate;
  gmp_randinit_default(randstate);
  mpz_class systime(time(NULL));
  gmp_randseed(randstate, systime.get_mpz_t());
  mpz_urandomm(priv.pk.e.get_mpz_t(), randstate, phi.get_mpz_t());
  //Now choose d and e - if they aren't compatible, choose again
  while(!mpz_invert(priv.d.get_mpz_t(), priv.pk.e.get_mpz_t(), phi.get_mpz_t())){
      mpz_urandomm(priv.pk.e.get_mpz_t(), randstate, phi.get_mpz_t());
  }
  return;
}

mpz_class encrypt(const mpz_class & plaintext, public_key & pk){
  mpz_class enc;
  mpz_powm(enc.get_mpz_t(), plaintext.get_mpz_t(), pk.e.get_mpz_t(), pk.n.get_mpz_t());
  return enc;
}

mpz_class decrypt(const mpz_class & ciphertext, private_key & priv){
  mpz_class dec;
  mpz_powm(dec.get_mpz_t(), ciphertext.get_mpz_t(), priv.d.get_mpz_t(), priv.pk.n.get_mpz_t());
  return dec;
}

//Note this only works with the toString method's result - not with the JSON!
public_key key_from_TPM_string(const std::string & s){
  public_key pk;
  std::string scrap;
  std::istringstream is(s);
  bool alreadySeenKeyBits = false;
  //Get key bits
  while(is >> scrap){
    if(scrap == "keyBits"){
      //Skip the first instance of "keyBits"
      if(!alreadySeenKeyBits){
        alreadySeenKeyBits = true;
        continue;
      }
      else{
        //Skip '='
        is >> scrap;
        unsigned int keyBits;
        is >> std::hex;
        is >> keyBits;
        pk.n = keyBits;
      }
    }
  }
  //Skip over the next 4 tokens
  for(unsigned int i = 0; i < 4; i++){
    is >> scrap;
  }
//Now get the exponent
  is >> std::hex;
  unsigned int exponent;
  is >> exponent;
  pk.e = exponent;

  return pk;
}



#endif
