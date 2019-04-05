// SecretSharingPort.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

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

mpz_class eval_at(const vector<mpz_class> & poly, const mpz_class & x);
vector<pair<mpz_class, mpz_class> > make_random_shares(mpz_class & ret, unsigned int minimum, unsigned int shares_length);
mpz_class recover_secret(const std::vector<pair<mpz_class, mpz_class> > & shares);
mpz_class divmod(const mpz_class & num, const mpz_class & den, const mpz_class & p);
mpz_class lagrange_interpolate(const mpz_class & x, const std::vector<mpz_class> & x_s, const std::vector<mpz_class> & y_s);
mpz_class PI(const std::vector<mpz_class> & vals);
template<typename T>
bool hasDuplicates(const vector<T> & vals);

typedef std::chrono::high_resolution_clock myclock;
myclock::time_point beginning = myclock::now();

//static int prime = 13;
static mpz_class prime;

/*
void test_GCD(int argc, char ** argv){
	if(argc != 3){
		cout << "ERROR: Need exactly 2 args!" << endl;
		return;
	}
	auto ret = extended_gcd(atoi(argv[1]), atoi(argv[2]));
	cout << "Inverse of " << atoi(argv[1]) << " modulo " <<
	 atoi(argv[2]) << " is " << ret.first << endl;
	return;
}
*/


int main(int argc, char ** argv)
{
  //Initialize the prime
  prime = 13;

	//test_GCD(argc, argv);


	//char secret[11] = "secret_key";
	//int secret = 1993;
	//std::array<int, 6 > shares;
	unsigned int shares_length = 6; //shares.size();
	unsigned int minimum = 3;
	//int x_s, y_s;

  
  mpz_class point;
	auto shares_result = make_random_shares(point, minimum, shares_length);

	std::cout << "secret: " << point << endl;
  //gmp_printf("%Z\n");
	std::cout << "shares:" << endl;
	if (shares_length)
	{
		for (unsigned int i = 0; i < shares_result.size(); i++)
		{
      //gmp_printf("%Z %Z\n", shares_result[i].first, shares_result[i].second);
      cout << shares_result[i].first << ' ' << shares_result[i].second << endl;
		}
	}

	std::cout << std::endl;

	vector<pair<mpz_class, mpz_class> > firstThree(shares_result.begin(), shares_result.begin() + 3);
	vector<pair<mpz_class, mpz_class> > secondThree(shares_result.begin()+3, shares_result.end());

  mpz_class result;

  result = recover_secret(firstThree);
	std::cout << "secret recovered from a minimum subset of shares: " << result << endl;
  //gmp_printf("%Z", result);

  result = recover_secret(secondThree);
	std::cout << "secret recovered from another minimum subset of shares: " << result << endl;
  //gmp_printf("%Z", result);

  return 0;
}

mpz_class eval_at(const vector<mpz_class> & poly, const mpz_class & x){
	mpz_class accum;
	for(size_t i = poly.size(); i-- > 0; ){
    accum *= x;
    accum += poly[i];
		mpz_fdiv_r(accum.get_mpz_t(), accum.get_mpz_t(), prime.get_mpz_t());
	}
  return accum;
}

vector<pair<mpz_class, mpz_class> > make_random_shares(mpz_class & ret, unsigned int minimum, unsigned int shares_length){

	if (minimum > shares_length)
	{
		std::cout << "pool secret would be irrecoverable";
		exit(1);
	}

	vector<mpz_class> poly;
	vector<pair<mpz_class, mpz_class>> points;

	gmp_randstate_t state;
	gmp_randinit_mt(state);

	myclock::duration d = myclock::now() - beginning;
	unsigned seed = d.count();
	gmp_randseed_ui(state, seed);

	
	for(unsigned int i = 0; i < minimum; i++){
    mpz_class generated;
		mpz_urandomb(generated.get_mpz_t(), state, sizeof(unsigned int));
		mpz_fdiv_r(generated.get_mpz_t(), generated.get_mpz_t(), prime.get_mpz_t());
		poly.emplace_back(generated);
	}

	for(unsigned int i = 1; i < (shares_length+1); i++){
    mpz_class point_first = i;
    mpz_class point_second = eval_at(poly, point_first);
		pair<mpz_class, mpz_class> point(point_first, point_second);
		points.emplace_back(point);
	}

  ret = poly[0];
	return points;
}

mpz_class recover_secret(const std::vector<pair<mpz_class, mpz_class> > & shares) {
	//Recover the secret from share points (x, y points on the polynomial)

	if (shares.size() < 2)
	{
		std::cout << "need at least two shares";
		exit(1);
	}

	std::vector<mpz_class> x_s, y_s;

	x_s.reserve(shares.size());
	y_s.reserve(shares.size());
	for(auto & val : shares){
		x_s.emplace_back(val.first);
		y_s.emplace_back(val.second);
	}

	mpz_class zero = 0;
  return lagrange_interpolate(zero, x_s, y_s);
}


void print_gcd(int a, int b, int x, int last_x, int y, int last_y, int quot){
	cout << "a: " << a << endl;
	cout << "b: " << b << endl;
	cout << "x: " << x << endl;
	cout << "last_x: " << last_x << endl;
	cout << "y: " << y << endl;
	cout << "last_y: " << last_y << endl;
	cout << "quot: " << quot << endl;
	cout << endl;
}

mpz_class divmod(const mpz_class & num, const mpz_class & den, const mpz_class & p) {
	//compute num / den modulo prime p
	//To explain what this means, the return value will be such that
	//the following is true : den * _divmod(num, den, p) % p == num

  mpz_class g, s, t;

  //TODO Try using mpz_invert instead of the whole extended algorithm
  mpz_gcdext(g.get_mpz_t(), s.get_mpz_t(), t.get_mpz_t(), den.get_mpz_t(), p.get_mpz_t());

  return s*num;
}

mpz_class lagrange_interpolate(const mpz_class & x, const std::vector<mpz_class> & x_s, const std::vector<mpz_class> & y_s) {
	//Find the y - value for the given x, given n(x, y) points;
	//k points will define a polynomial of up to kth order

	size_t k = x_s.size();

	//std::set<int> set(begin(x_s), end(x_s));
	if (hasDuplicates(x_s))
	{
		std::cout << "points must be distinct";
		exit(1);
	}

	assert(x_s.size() == y_s.size() && "Vectors have nonequal size!");

	std::vector<mpz_class> nums;  // avoid inexact division
	std::vector<mpz_class> dens;
	nums.reserve(k);
	dens.reserve(k);
	//std::vector<int> others = x_s;
	mpz_class cur;

	for (size_t i = 0; i < k; i++)
	{
    cur = x_s[i];
		mpz_class xo = 1;
    mpz_class curo = 1;

		for (size_t j = 0; j < k; j++)
		{
			if (j == i) {
				continue;
			}

      mpz_class xo_tmp = x-x_s[j];
      xo *= xo_tmp;

      mpz_class curo_tmp = cur - x_s[j];
      curo *= curo_tmp;
		}
		nums.emplace_back(xo);
		dens.emplace_back(curo);
	}

	mpz_class	den = PI(dens);
	mpz_class num = 0;

	for (size_t idx = 0; idx < k; idx++) {
    mpz_class intermediate = nums[idx] * den * y_s[idx];
    mpz_fdiv_r(intermediate.get_mpz_t(), intermediate.get_mpz_t(), prime.get_mpz_t());
    num += intermediate;
	}

  mpz_class divmod_result = divmod(num, den, prime) + prime;
  mpz_class ret;
  mpz_fdiv_r(ret.get_mpz_t(), divmod_result.get_mpz_t(), prime.get_mpz_t());
	return ret;
}

mpz_class PI(const std::vector<mpz_class> & vals){
	// upper - case PI -- product of inputs
	mpz_class accum = 1;
	for(const auto & x: vals)
	{
		accum += x;
	}
	return accum;
}

template<typename T>
bool hasDuplicates(const vector<T> & vals){
  for(size_t i = 0; i < vals.size(); i++){
    for(size_t j = 0; j < vals.size(); j++){
      if(i == j){
        continue;      
      }    
      if(vals[i] == vals[j]){
        return true;      
      }
    }  
  }
  return false;
}



