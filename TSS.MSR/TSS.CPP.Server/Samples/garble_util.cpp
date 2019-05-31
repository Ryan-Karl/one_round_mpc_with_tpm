#include <thread>
#include <math.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>
#include <exception>
#include <unordered_map>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <aes.h>
#include <modes.h>
#include "garble_util.h"
// http://www.cs.toronto.edu/~vlad/papers/XOR_ICALP08.pdf

using namespace std;

// Called by server.  Expects the structure of the circuit but not values relevant to garbling.
void get_garbled_circuit(Circuit * c) {
	//Get randomness from player info
	wire_value * R = random_wire(c->security);
	for (auto w_it = c->input_wires.begin(); w_it < c->input_wires.end(); w_it++) {
		Wire * w = *w_it;
		w->p[0] = random_bit();
		w->p[1] = !(w->p[0]);
		w->k[0] = random_wire(c->security);
		w->k[1] = xor_wire(w->k[0], R);
	}
	std::deque<Wire *> t_ordering;
	top_sort(t_ordering, c);
	while (!t_ordering.empty()) {
		Wire * w = t_ordering.back();
		t_ordering.pop_back();
		if (w->is_gate && w->g_type == GATE_XOR) {
			Wire * a = w->left_child;
			Wire * b = w->right_child;
			w->p[0] = (a->p[0] != b->p[0]);
			// This would work with xor(a->p1,b->p1), as well as xor(a->p0, b->p0),
			// it will always be the same value.
			w->p[1] = !(w->p[0]);
			w->k[0] = xor_wire(a->k[0], b->k[0]);
			w->k[1] = xor_wire(w->k[0], R);
		}
		else if (w->is_gate) {
			Wire * a = w->left_child;
			Wire * b = w->right_child;

			w->p[0] = random_bit();
			w->p[1] = !(w->p[0]);
			w->k[0] = random_wire(c->security);
			w->k[1] = xor_wire(w->k[0], R);

			for (int i_a = 0; i_a <= 1; i_a++) {
				for (int i_b = 0; i_b <= 1; i_b++) {
					bool out = eval_gate(w->g_type, i_a, i_b);
					wire_value * w_out = wire2garbling(w, out);
					wire_value * e = xor_wire(w_out, hash_wire(a->k[i_a], b->k[i_b], w->gate_number));
					int index = p_to_index(a->p[i_a], b->p[i_b]);
					w->garbled_labels[index] = e;
				}
			}
		}
	}

	// create garbled output tables
	for (auto w_it = c->output_wires.begin(); w_it < c->output_wires.end(); w_it++) {
		Wire * w = *w_it;
		bool e0 = hash_bool(w->k[0], "out", w->gate_number);
		bool e1 = !hash_bool(w->k[1], "out", w->gate_number);
		w->output_garble_info[w->p[0]] = e0;
		w->output_garble_info[w->p[1]] = e1;
	}
}

bool eval_gate(gate_type g, bool x, bool y) {
	unsigned char offset = p_to_index(x, y) << 0x1;
	return ((g & offset) != 0);
}

int p_to_index(bool p1, bool p0) {
	return (int)(p1 << 1) + (int)p0;
}

void eval_garbled_circuit(Circuit * c) {
	for (auto w_it = c->input_wires.begin(); w_it < c->input_wires.end(); w_it++) {
		Wire * w = *w_it;
		garbling2wire(w->label_kp, &(w->label_k), &(w->label_p));
	}
	std::deque<Wire *> t_ordering;
	top_sort(t_ordering, c);
	while (!t_ordering.empty()) {
		Wire * w = t_ordering.back();
		t_ordering.pop_back();
		if (w->is_gate && w->g_type == GATE_XOR) {
			Wire * a = w->left_child;
			Wire * b = w->right_child;
			w->label_p = (a->label_p != b->label_p);
			w->label_k = xor_wire(a->label_k, b->label_k);
		}
		else if (w->is_gate) {
			Wire * a = w->left_child;
			Wire * b = w->right_child;
			int index = p_to_index(a->label_p, b->label_p);
			wire_value * garbling = xor_wire(w->garbled_labels[index], hash_wire(a->label_k, b->label_k, w->gate_number));
			garbling2wire(garbling, &(w->label_k), &(w->label_p));
		}
	}
	for (auto w_it = c->output_wires.begin(); w_it < c->output_wires.end(); w_it++) {
		Wire * w = *w_it;
		bool out = (w->output_garble_info[w->label_p] != hash_bool(w->label_k, "out", w->gate_number));
		w->output_value = out;
	}
}

// the garbling is just the concatenation of w->kb and w->pb for b=which
wire_value * wire2garbling(const Wire * w, const bool which) {
	wire_value * k = w->k[which];
	int size = k->len + 1;
	wire_value * ret = new wire_value(size);
	for (int i = 0; i < size - 1; i++) {
		ret->set(i, k->get(i));
	}
	ret->set(size - 1, w->p[which]);
	return ret;
}

void garbling2wire(const wire_value *w, wire_value **k, bool *p) {
	int size = w->len - 1;
	if (*k == nullptr) {
		//TODO make sure this is the right size value
		*k = new wire_value(size);
	}
	for (int i = 0; i < size; i++) {
		(*k)->set(i, w->get(i));
	}
	*p = w->get(size);
}

#ifndef CHAR_WIDTH
#define CHAR_WIDTH 8
#endif

wire_value::wire_value(int size) {
	//assert(size > 0);
	  //bits = new char[size / CHAR_WIDTH]();
	bits = new char[(size / CHAR_WIDTH) + (size%CHAR_WIDTH ? 1 : 0)];
	len = size;
}

wire_value::~wire_value() {
	delete bits;
	bits = nullptr;
}

void wire_value::set(int i, bool b) {
	//assert(i >= 0 && i < len);
	if (b) {
		bits[i / CHAR_WIDTH] |= (1 << (i % CHAR_WIDTH));
	}
	else {
		bits[i / CHAR_WIDTH] &= ~(1 << (i % CHAR_WIDTH));
	}
}

bool wire_value::get(int i) const {
	//assert(i >= 0 && i < len);
	return (bits[i / CHAR_WIDTH] >> (i % CHAR_WIDTH)) & 1;
}

std::vector<unsigned char> wire_value::to_bytevec() const {
	std::vector<unsigned char> v;
	v.reserve(len*CHAR_WIDTH);
	v.assign(bits, bits + (len*CHAR_WIDTH));
	return v;
}

void wire_value::from_bytevec(const std::vector<unsigned char> * bits_in, const int i, const int nbits) {
	delete bits;
	bits = new char[nbits / CHAR_WIDTH + ((nbits%CHAR_WIDTH) ? 1 : 0)];
	auto it = (*bits_in).begin() + i;
	std::copy(it, it + (nbits / CHAR_WIDTH) + ((nbits%CHAR_WIDTH) ? 1 : 0), bits);
	len = nbits;
}

#include <openssl/sha.h>

//Output of SHA1 is 160 bits (20 bytes)
//#define SHA_OUTSIZE 20
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif
wire_value * hash_wire(wire_value * ka, wire_value * kb, int gate_number) {
	std::vector<unsigned char> fullbuf;
	unsigned int numbits = ka->len + kb->len + sizeof(gate_number)*CHAR_WIDTH;
	fullbuf.reserve(numbits / CHAR_WIDTH);
	fullbuf.insert(fullbuf.end(), ka->bits, (ka->bits) + (ka->len / CHAR_WIDTH) + ((ka->len % CHAR_WIDTH) ? 1 : 0));
	fullbuf.insert(fullbuf.end(), kb->bits, (kb->bits) + (kb->len / CHAR_WIDTH) + ((kb->len % CHAR_WIDTH) ? 1 : 0));
	for (unsigned int i = 0; i < sizeof(gate_number); i++) {
		fullbuf.push_back((gate_number >> (i*CHAR_WIDTH) & 0xFF));
	}
	wire_value * wv = new wire_value(SHA256_DIGEST_LENGTH*CHAR_WIDTH);
	SHA256(fullbuf.data(), fullbuf.size(), (unsigned char *)wv->bits);
	return wv;
}

bool hash_bool(wire_value * ke, char * str, int gate_number) {
	std::vector<unsigned char> fullbuf;
	unsigned int numbits = ke->len + strlen(str) + sizeof(gate_number)*CHAR_WIDTH;
	fullbuf.reserve(numbits / CHAR_WIDTH);
	fullbuf.insert(fullbuf.end(), ke->bits, (ke->bits) + (ke->len / CHAR_WIDTH) + ((ke->len % CHAR_WIDTH) ? 1 : 0));
	fullbuf.insert(fullbuf.end(), (unsigned char *)str, (unsigned char *)str + strlen(str));
	for (unsigned int i = 0; i < sizeof(gate_number); i++) {
		fullbuf.push_back((gate_number >> (i*CHAR_WIDTH) & 0xFF));
	}
	char hashout[SHA256_DIGEST_LENGTH];
	SHA256(fullbuf.data(), fullbuf.size(), (unsigned char *)hashout);
	return (hashout[0]) & 1;
}


wire_value * random_wire(int width) {
	//assert(width > 0);
	wire_value * wv = new wire_value(width);
	for (int i = 0; i < width / CHAR_WIDTH; i++) {
		wv->bits[i] = rand() & 0xFF;
	}
	return wv;
}

bool random_bit() {
	return rand() & 1;
}


wire_value * xor_wire(wire_value * w1, wire_value * w2) {
	int min_len = w1->len < w2->len ? w1->len : w2->len;
	wire_value * wv = new wire_value(min_len);
	int num_bytes = min_len / CHAR_WIDTH;
	if (min_len % CHAR_WIDTH) {
		num_bytes++;
	}
	for (int i = 0; i < num_bytes; i++) {
		wv->bits[i] = w1->bits[i] ^ w2->bits[i];
	}
	return wv;
}

enum NodeMark { TEMPORARY, PERMANENT };

void visit(Wire * w,
	std::unordered_map<Wire *, NodeMark> & nodemap,
	unsigned int & num_not_permanent, std::deque<Wire *> & destination) {
	auto findwire = nodemap.find(w);
	if (findwire != nodemap.end()) {
		NodeMark currmark = (*findwire).second;
		if (currmark == PERMANENT) { return; }
		else {
			std::cerr << "ERROR: not a DAG" << std::endl;
			throw std::logic_error("ERROR: not a DAG");
		}
	}
	nodemap[w] = TEMPORARY;
	//auto currnode = nodemap.find(w);
	if (w->is_gate) {
		visit(w->left_child, nodemap, num_not_permanent, destination);
		visit(w->right_child, nodemap, num_not_permanent, destination);
	}
	nodemap[w] = PERMANENT;
	num_not_permanent--;
	destination.push_front(w);
}

void top_sort(std::deque<Wire *> & destination, const Circuit * circuit) {
	unsigned int num_not_permanent = (unsigned int)circuit->n_wires;
	//Construct list of nodes
	std::deque<Wire *> nodelist;
	nodelist.insert(nodelist.end(), circuit->output_wires.begin(), circuit->output_wires.end());
	nodelist.insert(nodelist.end(), circuit->input_wires.begin(), circuit->input_wires.end());
	std::unordered_map<Wire *, NodeMark> nodemap;
	nodemap.reserve(num_not_permanent);
	while (num_not_permanent && nodelist.size()) {
		Wire * nextwire = nodelist.back();
		nodelist.pop_back();
		visit(nextwire, nodemap, num_not_permanent, destination);
	}
}

void wire_value::xor_with(wire_value * rhs) {
	int newlen = (len < rhs->len) ? len : rhs->len;
	char * newbuf = new char[newlen / CHAR_WIDTH + ((newlen % CHAR_WIDTH) ? 1 : 0)];
	for (int i = 0; i < newlen / CHAR_WIDTH; i++) {
		newbuf[i] = bits[i] ^ rhs->bits[i];
	}
	if (newlen % CHAR_WIDTH) {
		newbuf[(newlen / CHAR_WIDTH)] = bits[newlen / CHAR_WIDTH] ^ rhs->bits[newlen / CHAR_WIDTH];
	}
	delete bits;
	bits = newbuf;
	len = newlen;
}

void circuit_to_bytevec(Circuit * c, std::vector<unsigned char> * v) {
	std::deque<Wire *> t_ordering;
	top_sort(t_ordering, c);
	while (!t_ordering.empty()) {
		Wire * w = t_ordering.back();
		t_ordering.pop_back();
		if (w->is_gate && w->g_type != GATE_XOR) {
			//info
			for (int i = 0; i < 4; i++) {
				std::vector<unsigned char> bv = w->garbled_labels[i]->to_bytevec();
				v->insert(v->end(), bv.begin(), bv.end());
			}
		}
		if (w->is_root) {
			for (int i = 0; i < 2; i++) {
				if (w->output_garble_info[i]) {
					v->push_back(1);
				}
				else {
					v->push_back(0);
				}
			}
		}
	}
}

void bytevec_to_circuit(Circuit * c, std::vector<unsigned char> * v) {
	std::deque<Wire *> t_ordering;
	top_sort(t_ordering, c);
	int at = 0;
	while (!t_ordering.empty()) {
		Wire * w = t_ordering.back();
		t_ordering.pop_back();
		if (w->is_gate && w->g_type != GATE_XOR) {
			//info
			for (int i = 0; i < 4; i++) {
				w->garbled_labels[i] = new wire_value(c->security + 1);
				w->garbled_labels[i]->from_bytevec(v, at, c->security + 1);
				at += (c->security + 1) / CHAR_WIDTH;
			}
		}
		if (w->is_root) {
			for (int i = 0; i < 2; i++) {
				if ((*v)[at]) {
					w->output_garble_info[i] = true;
				}
				else {
					w->output_garble_info[i] = false;
				}
				at++;
			}
		}
	}
}


Wire::Wire() {
	k[0] = k[1] = nullptr;
	garbled_labels[0]
		= garbled_labels[1]
		= garbled_labels[2]
		= garbled_labels[3]
		= nullptr;
	left_child = right_child = nullptr;
	label_kp = label_k = nullptr;
}

Wire::~Wire() {
	delete k[0];
	delete k[1];
	delete garbled_labels[0];
	delete garbled_labels[1];
	delete garbled_labels[2];
	delete garbled_labels[3];
	//TODO figure out if we need to delete children
	delete label_kp;
	delete label_k;
}
