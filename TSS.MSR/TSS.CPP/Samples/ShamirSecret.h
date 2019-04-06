

#ifndef SHAMIRSECRET_H
#define SHAMIRSECRET_H

#define NOMINMAX

//#include "pch.h"
//#include <iostream>
//#include <cassert>
#include <ctime>


#include <vector>
#include <chrono>
#include <random>
#include <utility>

//#include <array>
//#include <set>
#include <stdexcept>


#ifdef __linux__
#include <gmp.h>
#include <gmpxx.h>
#elif defined(WIN32)
#undef min
#undef max
#include <mpir.h>
#include <mpirxx.h>
#else
#error No OS defined!
#endif

//typedef std::chrono::high_resolution_clock myclock;
//const static myclock::time_point beginning = myclock::now();



class ShamirSecret{

private:



  mpz_class prime;
  //char * secret;
  unsigned int num_shares;
  unsigned int min_shares_to_recover;

  static bool hasDuplicates(const std::vector<std::pair<mpz_class, mpz_class> > & shares);
  static mpz_class PI(const std::vector<mpz_class> & vals);
  mpz_class eval_at(const std::vector<mpz_class> & poly, const mpz_class & x) const ;
  mpz_class divmod(const mpz_class & num, const mpz_class & den) const ;

public:
  ShamirSecret(mpz_class pr, unsigned int shares, unsigned int recover): prime(pr), num_shares(shares), min_shares_to_recover(recover) {
    if(recover > shares){
      throw std::logic_error("Pool secret is irrecoverable");
    }
  }

  std::vector<std::pair<mpz_class, mpz_class> > getShares(const char * secret) const ;
  std::vector<std::pair<mpz_class, mpz_class> > getShares(const mpz_class & secret) const ;

  mpz_class getSecret(const std::vector<std::pair<mpz_class, mpz_class> > & shares) const ;
  const char * getSecretString(std::vector<std::pair<mpz_class, mpz_class> > & shares) const ;
};

mpz_class ShamirSecret::PI(const std::vector<mpz_class> & vals){
  mpz_class accum = 1;
  for(const auto & x: vals){accum *= x;}
  return accum;
}

mpz_class ShamirSecret::getSecret(const std::vector<std::pair<mpz_class, mpz_class> > & shares) const {
  #ifdef DEBUG
  if(hasDuplicates(shares)){
    throw std::logic_error("Shares contain duplicate x-values");
  }
  #endif

  size_t k = shares.size();

  std::vector<mpz_class> nums; 
  std::vector<mpz_class> dens;
  nums.reserve(k);
  dens.reserve(k);

  for (size_t i = 0; i < k; i++){
    mpz_class xo = 1;
    mpz_class curo = 1;

    for (size_t j = 0; j < k; j++){
      if (j == i) {
        continue;
       }

      mpz_class xo_tmp = 0-shares[j].first;
      xo *= xo_tmp;

      mpz_class curo_tmp = shares[i].first - shares[j].first;
      curo *= curo_tmp;
    }

    nums.push_back(xo);
    dens.push_back(curo);
  }

  mpz_class den = PI(dens);
  mpz_class num = 0;

  for (size_t idx = 0; idx < k; idx++) {
    mpz_class intermediate = nums[idx] * den * shares[idx].second;
    mpz_fdiv_r(intermediate.get_mpz_t(), intermediate.get_mpz_t(), prime.get_mpz_t());
    intermediate = divmod(intermediate, dens[idx]);
    //cout << intermediate << " " << endl;
    num += intermediate;
  }

  mpz_class divmod_result = divmod(num, den) + prime;
  mpz_class ret;
  mpz_fdiv_r(ret.get_mpz_t(), divmod_result.get_mpz_t(), prime.get_mpz_t());
  return ret;
}

const char * ShamirSecret::getSecretString(std::vector<std::pair<mpz_class, mpz_class> > & shares) const {
  mpz_class mpz_result = getSecret(shares);
  return mpz_result.get_str().c_str();
}


std::vector<std::pair<mpz_class, mpz_class> > ShamirSecret::getShares(const mpz_class & secret) const {
  std::vector<mpz_class> poly;
  std::vector<std::pair<mpz_class, mpz_class>> points;
  poly.reserve(num_shares);
  points.reserve(num_shares);
  //Random initialization - may need to change this for cryptographic security
  gmp_randstate_t state;
  gmp_randinit_mt(state);
  //myclock::duration d = myclock::now() - beginning;
  //Get a random seed
  std::random_device rd;
  unsigned int seed = rd();
  gmp_randseed_ui(state, seed);
  //Instead of random initialization, set the secret to be given by the user
  mpz_class poly_secret = secret;
  poly.push_back(poly_secret);
  //Randomly initialize the rest of the polynomial
  for(unsigned int i = 1; i < min_shares_to_recover; i++){
    mpz_class generated;
    mpz_urandomb(generated.get_mpz_t(), state, sizeof(unsigned int));
    mpz_fdiv_r(generated.get_mpz_t(), generated.get_mpz_t(), prime.get_mpz_t());
    poly.push_back(generated);
  }
  //Evaluate the polynomial
  for(unsigned int i = 1; i < (num_shares+1); i++){
    mpz_class point_first = i;
    mpz_class point_second = eval_at(poly, point_first);
    std::pair<mpz_class, mpz_class> point(point_first, point_second);
    points.push_back(point);
  }

  return points;
}

std::vector<std::pair<mpz_class, mpz_class> > ShamirSecret::getShares(const char * secret) const{
  mpz_class mpz_secret(secret);
  return getShares(mpz_secret);
}

bool ShamirSecret::hasDuplicates(const std::vector<std::pair<mpz_class, mpz_class> > & shares){
  for(size_t i = 0; i < shares.size(); i++){
    for(size_t j = 0; j < shares.size(); j++){
      if(i==j){continue;}
      if(shares[i].first == shares[j].first){return true;}
    }
  }
  return false;
}

mpz_class ShamirSecret::eval_at(const std::vector<mpz_class> & poly, const mpz_class & x) const {
    mpz_class accum;
    for(size_t i = poly.size(); i-- > 0; ){
      accum *= x;
      accum += poly[i];
      mpz_fdiv_r(accum.get_mpz_t(), accum.get_mpz_t(), prime.get_mpz_t());
    }
    return accum;
}

mpz_class ShamirSecret::divmod(const mpz_class & num, const mpz_class & den) const {
    mpz_class g, s, t;
    //TODO Try using mpz_invert instead of the whole extended algorithm
    mpz_gcdext(g.get_mpz_t(), s.get_mpz_t(), t.get_mpz_t(), den.get_mpz_t(), prime.get_mpz_t());
    return s*num;
}

#endif
