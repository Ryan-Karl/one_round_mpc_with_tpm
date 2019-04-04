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


#ifdef linux
#include <gmp.h>
#endif
#ifdef _WIN32
#include <mpir.h>
#endif


using std::pair;
using std::vector;
using std::cout;
using std::endl;




int eval_at(const std::vector<int> & poly, int x);
pair<int, vector<pair<int,int>>> make_random_shares(int minimum, int shares_length);
int recover_secret(const std::vector<pair<int,int>> & shares);
std::pair<int, int> extended_gcd(int a, int b);
int divmod(int num, int den, int p);
int lagrange_interpolate(int x, const std::vector<int> & x_coordinates, const std::vector<int> & shares);
int PI(const std::vector<int> & vals);

typedef std::chrono::high_resolution_clock myclock;
myclock::time_point beginning = myclock::now();

//static int prime = 13;
static mpz_t prime;


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


int main(int argc, char ** argv)
{
  //Initialize the prime
  mpz_init(prime);
  mpz_set_ui(prime, 13);

	//test_GCD(argc, argv);


	//char secret[11] = "secret_key";
	int secret = 1993;
	//std::array<int, 6 > shares;
	int shares_length = 6; //shares.size();
	int minimum = 3;
	//int x_s, y_s;

	
	auto shares_result = make_random_shares(minimum, shares_length);

	std::cout << "secret: " << shares_result.first << std::endl;
	std::cout << "shares:" << endl;
	if (shares_length)
	{
		for (unsigned int i = 0; i < shares_result.second.size(); i++)
		{
			std::cout << shares_result.second[i].first << ' ' << shares_result.second[i].second << endl;
		}
	}

	std::cout << std::endl;

	vector<pair<int,int>> firstThree(shares_result.second.begin(), shares_result.second.begin() + 3);
	vector<pair<int,int>> secondThree(shares_result.second.begin()+3, shares_result.second.end());

	std::cout << "secret recovered from a minimum subset of shares: " << recover_secret(firstThree) << std::endl;
	std::cout << "secret recovered from another minimum subset of shares: " << recover_secret(secondThree) << std::endl;

  return 0;

}


int eval_at(const std::vector<int> & poly, int x) {
	//evaluates polynomial (coefficient tuple) at x, used to generate a
	//shamir pool in make_random_shares below.

	int accum = 0;
	for (unsigned int i = poly.size(); i-- > 0;)//coeff in reversed(poly))
	{
		int coeff = poly[i];
		accum *= x;
		accum += coeff;
		accum %= prime;
	}
	return accum;
}

pair<int, vector<pair<int,int>>> make_random_shares(int minimum, int shares_length) {
	//First returned is secret, second is points.
	//Each point is a pair. First is the argument, second is the value.
	//Generates a random shamir pool, returns the secret and the share points.
	std::vector<int> poly;
	std::vector<pair<int,int>> points;

	if (minimum > shares_length)
	{
		std::cout << "pool secret would be irrecoverable";
		exit(1);
	}

	myclock::duration d = myclock::now() - beginning;
	unsigned seed1 = d.count();
	std::mt19937 generator(seed1);


	for (unsigned int i = 0; i < minimum; i++)
	{

		poly.push_back(generator() % prime);
	}


	for (unsigned int i = 1; i < (shares_length + 1); i++)
	{
		pair<int,int> point;
		point.second = eval_at(poly, i);
		point.first = i;
		points.push_back(point);
	}

	return std::pair<int, vector<pair<int,int>>>(poly[0], points);
}

mpz_t recover_secret(const std::vector<pair<mpz_t,mpz_t>> & shares) {
	//Recover the secret from share points (x, y points on the polynomial)

	if (shares.size() < 2)
	{
		std::cout << "need at least two shares";
		exit(1);
	}

	std::vector<mpz_t> x_s, y_s;

	/*for (unsigned int i = 0; i < shares.size(); i++)
	{
		x_s.push_back(i + 1);
		y_s.push_back(shares[i]);

		std::cout << "x_s is " << x_s[i] << std::endl << "y_s is " << y_s[i] << std::endl;

	}*/

	x_s.reserve(shares.size());
	y_s.reserve(shares.size());
	for(auto & val : shares){
		x_s.push_back(val.first);
		y_s.push_back(val.second);
	}


	return lagrange_interpolate(0, x_s, y_s); //Prime is currently global
	//return lagrange_interpolate(0, x_s, y_s, prime);
}

/*
std::pair<int, int> extended_gcd_jon(int a, int b){
	if(!a){
		return pair<int,int>(0,1);
	}
}
*/

//Used for testing GCD
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


mpz_t divmod(mpz_t num, mpz_t den, mpz_t p) {
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

	return s;
}

mpz_t lagrange_interpolate(mpz_t x, const std::vector<mpz_t> & x_s, const std::vector<mpz_t> & y_s) {
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
    mpz_init_si(xo, 1);
    mpz_init_si(curo, 1);

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

	mpz_t	den = PI(dens);

	mpz_t num;
  mpz_init(num);

	for (size_t idx = 0; idx < k; idx++) {

    mpz_t result;
    mpz_init(result);
    mpz_mul(result, nums[idx], den);
    mpz_mul(result, result, y_s[idx]);
    mpz_fdiv_r(result, result, prime);
    mpz_t divmod_result = divmod(result, dens[idx], prime);
    mpz_add(num, num, divmod_result);
	}

  mpz_t tmp = divmod(num, den, prime);
  mpz_add(tmp, tmp, prime);
  mpz_fdiv_r(tmp, tmp, prime);
	return tmp;

}

mpz_t PI(const std::vector<mpz_t> & vals) {
	// upper - case PI -- product of inputs
	mpz_t accum;
  mpz_init(accum);
  mpz_set_si(accum, 1)

	for (const auto & x: vals)
	{
		mpz_mul(accum, accum, x);
	}

	return accum;
}
