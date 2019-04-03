// SecretSharingPort.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <utility>
#include <array>
#include <set>
#include <mpir.h>

//#include <mpir.h>

int eval_at(const std::vector<int> & poly, int x);
std::pair<int, std::vector<int> > make_random_shares(int minimum, int shares_length);
int recover_secret(const std::vector<int> & shares, const std::vector<int> & x_coordinates);
std::pair<int, int> extended_gcd(int a, int b);
int divmod(int num, int den, int p);
int lagrange_interpolate(int x, const std::vector<int> & x_coordinates, const std::vector<int> & shares);
int PI(const std::vector<int> & vals);

typedef std::chrono::high_resolution_clock myclock;
myclock::time_point beginning = myclock::now();
static int prime = 13;


int main()
{
	//char secret[11] = "secret_key";
	int secret = 1993;
	//std::array<int, 6 > shares;
	int shares_length = 6; //shares.size();
	int minimum = 3;
	//int x_s, y_s;

	auto shares_result = make_random_shares(minimum, shares_length);

	std::cout << "secret: " << shares_result.first << std::endl;
	std::cout << "shares:";
	if (shares_length)
	{
		for (unsigned int i = 0; i < shares_result.second.size(); i++)
		{
			std::cout << ' ' << shares_result.second[i];
		}
	}

	std::cout << std::endl;

	std::vector<int> recovered_shares;
	std::vector<int> run1 = { 1, 2, 3};
	std::vector<int> run2 = { 4, 5, 6};


	recovered_shares.push_back(shares_result.second[0]);
	recovered_shares.push_back(shares_result.second[1]);
	recovered_shares.push_back(shares_result.second[2]);

	std::cout << "secret recovered from minimum subset of shares:             " << recover_secret(run1, recovered_shares) << std::endl; 

	recovered_shares[0] = (shares_result.second[3]);
	recovered_shares[1] = (shares_result.second[4]);
	recovered_shares[2] = (shares_result.second[5]);

	std::cout << "secret recovered from a different minimum subset of shares: " << recover_secret(run2, recovered_shares) << std::endl;
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

std::pair<int, std::vector<int>> make_random_shares(int minimum, int shares_length) {
	//First returned is secret, second is points.
	//Generates a random shamir pool, returns the secret and the share points.
	std::vector<int> poly;
	std::vector<int> points;

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
		points.push_back(eval_at(poly, i));
	}

	return std::pair<int, std::vector<int>>(poly[0], points);
}

int recover_secret(const std::vector<int> & shares, const std::vector<int> & x_coordinates) {
	//Recover the secret from share points (x, y points on the polynomial)

	if (shares.size() < 2)
	{
		std::cout << "need at least two shares";
		exit(1);
	}

	std::vector<int> x_s, y_s;

	/*for (unsigned int i = 0; i < shares.size(); i++)
	{
		x_s.push_back(i + 1);
		y_s.push_back(shares[i]);

		std::cout << "x_s is " << x_s[i] << std::endl << "y_s is " << y_s[i] << std::endl;

	}*/

	return lagrange_interpolate(0, x_coordinates, shares);
	//return lagrange_interpolate(0, x_s, y_s, prime);
}

std::pair<int, int> extended_gcd(int a, int b) {
	//division in integers modulus p means finding the inverse of the
	//denominator modulo p and then multiplying the numerator by this
	//inverse(Note: inverse of A is B such that A*B % p == 1) this can
	//be computed via extended Euclidean algorithm
	//http ://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
	int x = 0, last_x = 1, y = 1, last_y = 0;

	while (b != 0) {
		int quot = floor(a / b);

		int temp_a = a;
		a = b;
		b = temp_a % b;

		int temp_x = x;
		x = (last_x - quot * x);
		last_x = x;

		int temp_y = y;
		y = (last_y - quot * y);
		last_y = y;
	}

	return std::pair<int, int>(last_x, last_y);
}

int divmod(int num, int den, int p) {
	//compute num / den modulo prime p
	//To explain what this means, the return value will be such that
	//the following is true : den * _divmod(num, den, p) % p == num

	std::pair<int, int> gcd_result = extended_gcd(den, p);

	return (gcd_result.first * num);
}

int lagrange_interpolate(int x, const std::vector<int> & x_s, const std::vector<int> & y_s) {
	//Find the y - value for the given x, given n(x, y) points;
	//k points will define a polynomial of up to kth order

	unsigned int k = x_s.size();
	std::set<int> set(begin(x_s), end(x_s));
	if (k != (set.size()))
	{
		std::cout << "points must be distinct";
		exit(1);
	}

	std::vector<int> nums;  // avoid inexact division
	std::vector<int> dens;
	nums.reserve(k);
	dens.reserve(k);
	//std::vector<int> others = x_s;
	int cur;

	for (unsigned int i = 0; i < k; i++)
	{
		cur = x_s[i];
		//nums.pop_back();

		int xo = 1;
		int curo = 1;

		for (unsigned int j = 0; j < k; j++)
		{
			if (j == i) {
				continue;
			}

			xo *= x - x_s[j];

			//std::vector<int> 

			curo *= cur - x_s[j];

		}

		nums.push_back(xo);
		dens.push_back(curo);

	}

	int	den = PI(dens);

	int num = 0;
	for (unsigned int idx = 0; idx < k; idx++) {
		num += divmod((nums[idx] * den * y_s[idx]) % prime, dens[idx], prime);
	}

	return (divmod(num, den, prime) + prime) % prime;

}

int PI(const std::vector<int> & vals) {
	// upper - case PI -- product of inputs
	int accum = 1;

	for (unsigned int i = 0; i < vals.size(); i++)
	{
		accum *= vals[i];
	}

	return accum;
}

/*'''

*/
