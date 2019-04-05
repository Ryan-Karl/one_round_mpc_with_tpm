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
#elif defined(WIN32)
#include <mpir.h>
#else
#error No OS defined!
#endif


using std::pair;
using std::vector;
using std::cout;
using std::endl;

void eval_at(mpz_t ret, const vector<mpz_t> & poly, mpz_t x);
vector<pair<mpz_t, mpz_t> > make_random_shares(mpz_t ret, unsigned int minimum, unsigned int num_shares);
void recover_secret(mpz_t ret, const std::vector<pair<mpz_t,mpz_t> > & shares);
void divmod(mpz_t ret, mpz_t num, mpz_t den, mpz_t p);
void lagrange_interpolate(mpz_t ret, mpz_t x, const std::vector<mpz_t> & x_s, const std::vector<mpz_t> & y_s);
void PI(mpz_t ret, const std::vector<mpz_t> & vals);

typedef std::chrono::high_resolution_clock myclock;
myclock::time_point beginning = myclock::now();

//static int prime = 13;
static mpz_t prime;

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
  mpz_init(prime);
  mpz_set_ui(prime, 13);

	//test_GCD(argc, argv);


	//char secret[11] = "secret_key";
	//int secret = 1993;
	//std::array<int, 6 > shares;
	int shares_length = 6; //shares.size();
	int minimum = 3;
	//int x_s, y_s;

  
  mpz_t point;
  mpz_init(point);	
	auto shares_result = make_random_shares(point, minimum, shares_length);

	std::cout << "secret: ";
  gmp_printf("%Z\n");
	std::cout << "shares:" << endl;
	if (shares_length)
	{
		for (unsigned int i = 0; i < shares_result.size(); i++)
		{
      gmp_printf("%Z %Z\n", shares_result[i].first, shares_result[i].second);
		}
	}

	std::cout << std::endl;

	vector<pair<mpz_t,mpz_t> > firstThree(shares_result.begin(), shares_result.begin() + 3);
	vector<pair<mpz_t,mpz_t> > secondThree(shares_result.begin()+3, shares_result.end());

  mpz_t result;
  mpz_init(result);

  recover_secret(result, firstThree);
	std::cout << "secret recovered from a minimum subset of shares: ";
  gmp_printf("%Z", result);

  recover_secret(result, secondThree);
	std::cout << "secret recovered from another minimum subset of shares: ";
  gmp_printf("%Z", result);

  return 0;

}

void eval_at(mpz_t ret, const vector<mpz_t> & poly, mpz_t x){
	mpz_t accum;
	mpz_init(accum);
	for(size_t i = poly.size(); i-- > 0; ){
		mpz_mul(accum, accum, x);
		mpz_add(accum, accum, poly[i]);
		mpz_fdiv_r(accum, accum, prime);
	}
  mpz_set(ret, accum);
	return;
}

vector<pair<mpz_t, mpz_t> > make_random_shares(mpz_t ret, unsigned int minimum, unsigned int shares_length){

	if (minimum > shares_length)
	{
		std::cout << "pool secret would be irrecoverable";
		exit(1);
	}

	vector<mpz_t> poly;
	vector<pair<mpz_t, mpz_t>> points;

	gmp_randstate_t state;
	gmp_randinit_mt(state);

	myclock::duration d = myclock::now() - beginning;
	unsigned seed = d.count();
	gmp_randseed_ui(state, seed);

	mpz_t generated;
	mpz_init(generated);

	for(unsigned int i = 0; i < minimum; i++){
		mpz_urandomb(generated, state, sizeof(unsigned int));
		mpz_t tmp;
		mpz_init(tmp);
		mpz_set(tmp, generated);
		mpz_fdiv_r(tmp, tmp, prime);
		poly.push_back(tmp);
	}

	for(unsigned int i = 1; i < (shares_length+1); i++){
		pair<mpz_t, mpz_t> point;
    mpz_init(point.first);
    mpz_init(point.second);
		mpz_t mpz_i;
		mpz_init(mpz_i);
		mpz_set_ui(mpz_i, i);
		eval_at(point.second, poly, mpz_i);
		mpz_set(point.first, mpz_i);
		points.push_back(point);
	}

  mpz_set(ret, poly[0]);
	return points;
}

void recover_secret(mpz_t ret, const std::vector<pair<mpz_t,mpz_t> > & shares) {
	//Recover the secret from share points (x, y points on the polynomial)

	if (shares.size() < 2)
	{
		std::cout << "need at least two shares";
		exit(1);
	}

	std::vector<mpz_t> x_s, y_s;


	x_s.reserve(shares.size());
	y_s.reserve(shares.size());
	for(auto & val : shares){
		x_s.push_back(val.first);
		y_s.push_back(val.second);
	}

	mpz_t zero;
	mpz_init(zero);
  lagrange_interpolate(ret, zero, x_s, y_s);
  return;
	//return lagrange_interpolate(zero, x_s, y_s); //Prime is currently global
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

void divmod(mpz_t ret, mpz_t num, mpz_t den, mpz_t p) {
	//compute num / den modulo prime p
	//To explain what this means, the return value will be such that
	//the following is true : den * _divmod(num, den, p) % p == num

	//std::pair<int, int> gcd_result = extended_gcd(den, p);

  mpz_t g, s, t;
  mpz_init(g);
  mpz_init(s);
  mpz_init(t);

  //Try using mpz_invert instead of the whole extended algorithm
  mpz_gcdext(g, s, t, den, p);

  mpz_mul(s, s, num);
  mpz_set(ret, s);
  return;
}

void lagrange_interpolate(mpz_t ret, mpz_t x, const std::vector<mpz_t> & x_s, const std::vector<mpz_t> & y_s) {
	//Find the y - value for the given x, given n(x, y) points;
	//k points will define a polynomial of up to kth order

	size_t k = x_s.size();
	std::set<int> set(begin(x_s), end(x_s));
	if (k != (set.size()))
	{
		std::cout << "points must be distinct";
		exit(1);
	}
	assert(x_s.size() == y_s.size() && "Vectors have nonequal size!");

	std::vector<mpz_t> nums;  // avoid inexact division
	std::vector<mpz_t> dens;
	nums.reserve(k);
	dens.reserve(k);
	//std::vector<int> others = x_s;
	mpz_t cur;
  mpz_init(cur);

	for (size_t i = 0; i < k; i++)
	{
		mpz_set(cur, x_s[i]);
		//nums.pop_back();

		mpz_t xo, curo;
    mpz_init_set_si(xo, 1);
    mpz_init_set_si(curo, 1);

		for (size_t j = 0; j < k; j++)
		{
			if (j == i) {
				continue;
			}

      mpz_t xo_tmp;
      mpz_init(xo_tmp);      
      mpz_sub(xo_tmp, x, x_s[j]);
      mpz_mul(xo, xo, xo_tmp);


      mpz_t curo_tmp;
      mpz_init(curo_tmp);      
      mpz_sub(curo_tmp, cur, x_s[j]);
      mpz_mul(curo, curo, curo);

		}

		nums.push_back(xo);
		dens.push_back(curo);

	}

	mpz_t	den;
  mpz_init(den);
  PI(den, dens);

	mpz_t num;
  mpz_init(num);

	for (size_t idx = 0; idx < k; idx++) {

    mpz_t result;
    mpz_init(result);
    mpz_mul(result, nums[idx], den);
    mpz_mul(result, result, y_s[idx]);
    mpz_fdiv_r(result, result, prime);
    mpz_t divmod_result;
    mpz_init(divmod_result);
    divmod(divmod_result, result, dens[idx], prime);
    mpz_add(num, num, divmod_result);
	}

  mpz_t tmp;
  mpz_init(tmp);
  divmod(tmp, num, den, prime);
  mpz_add(tmp, tmp, prime);
  mpz_fdiv_r(tmp, tmp, prime);
  mpz_set(ret, tmp);
	return;

}

void PI(mpz_t ret, const std::vector<mpz_t> & vals){
	// upper - case PI -- product of inputs
	mpz_t accum;
  mpz_init(accum);
  mpz_set_si(accum, 1);

	for (const auto & x: vals)
	{
		mpz_mul(accum, accum, x);
	}
  mpz_set(ret, accum);
	return;
}
