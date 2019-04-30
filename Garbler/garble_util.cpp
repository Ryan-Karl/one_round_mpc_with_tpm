#include <thread>
#include <math.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "garble_util.h"
// http://www.cs.toronto.edu/~vlad/papers/XOR_ICALP08.pdf

using namespace std;

// Called by server.  Expects the structure of the circuit but not values relevant to garbling.
void get_garbled_circuit(Circuit * c) {
  //Get randomness from player info
  wire_value * R = random_wire(c->security);
  for (auto w_it = c->input_wires.begin(); w_it<c->input_wires.end(); w++) {
    Wire * w = *w_it;
    w->p[0] = random_bit();
    w->p[1] = !(w->p[0]);
    w->k[0] = random_wire(c->security);
    w->k[1] = xor_wire(w->k[0], R);
  }
  std::deque<Wire *> t_ordering;
  top_sort(t_ordering, circuit);
  while (!t_ordering.empty()) {
    Wire * w = t_ordering.pop();
    if (w->is_gate && w->gate_type == GATE_XOR) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;
      w->p[0] = (a->p[0] != b->p[0]);
      // This would work with xor(a->p1,b->p1), as well as xor(a->p0, b->p0),
      // it will always be the same value.
      w->p[1] = !(w->p[0]);
      w->k[0] = xor_wire(a->k[0], b->k[0]);
      w->k[1] = xor_wire(w->k[0], R);
    } else if (w->is_gate) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;

      w->p[0] = random_bit();
      w->p[1] = !(i->p[0]);
      w->k[0] = random_wire(c->security);
      w->k[1] = xor_wire(i->k[0], R);

      for (int i_a=0;i_a<=1;i_a++) {
        for (int i_b=0;i_b<=1;i_b++) {
          bool out = eval_gate(w->gate_type, i_a, i_b);
          wire_value * w_out = wire2garbling(w, out);
          wire * e = xor_wire(w_out, hash(a->k[i_a], b->k[i_b], w->gate_number));
          int index = p_to_index(a->p[i_a], b->p[i_b]);
          w->garbled_labels[index] = e;
        }
      }
    }
  }

  // create garbled output tables
  for (auto w_it = c->output_wires.begin(); w_it<c->output_wires.end(); w++) {
    Wire * w = *w_it;
    bool e0 = hash(w->k[0], "out", w->gate_number);
    bool e1 = !hash(w->k[1], "out", w->gate_number);
    w->output_garble_info[w->p[0]] = e0;
    w->output_garble_info[w->p[1]] = e1;
  }
}

bool eval_gate(gate_type g, bool x, bool y) {
  unsigned char offset = p_to_index(x, y) << 0x1;
  return ((gate_type & offset) != 0);
}

int p_to_index(bool p1, bool p0) {
  return (int)(p1 << 1) + (int)p0;
}

void eval_garbled_circuit(ClientCircuit * c) {
  for (auto w_it = c->input_wires.begin(); w_it<c->input_wires.end(); w++) {
    garbling2wire(w->kp, w->k, &(w->p));
  }
  std::deque<Wire *> t_ordering;
  top_sort(t_ordering, circuit);
  while (!t_ordering.empty()) {
    Wire * w = t_ordering.pop();
    if (w->is_gate && w->gate_type == GATE_XOR) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;
      w->label_p = (a->label_p != b->label_p);
      w->label_k = xor_wire(a->label_k, b->label_k);
    } else if (w->is_gate) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;
      int index = p_to_index(a->label_p, b->label_p);
      wire_value * garbling = xor_wire(w->garbled_labels[index], hash(a->label_k, b->label_k, w->gate_number));
      garbling2wire(garbling, w->label_k, w->label_p);
    }
  }
  for (auto w_it = c->output_wires.begin(); w_it<c->output_wires.end(); w++) {
    Wire * w = *w_it;
    bool out = (w->output_garble_info[w->label_p] != hash(w->label_k, "out", w->gate_number));
    w->output_value = out;
  }
}

// the garbling is just the concatenation of w->kb and w->pb for b=which
wire_value * wire2garbling(const Wire * w, const bool which) {
  wire_value * k = w->k[which]
  int size = k->size + 1;
  wire_value * ret = new wire_value(size);
  for (int i = 0; i < size - 1; i++) {
    ret->set(i, k->get(i));
  }
  ret->set(size-1, w->p[which]->get(i));
  return ret;
}

void garbling2wire(const wire_value *w, wire_value *k, bool *p) {
  int size = w->size - 1;
  for (int i = 0; i < size; i++) {
    k->set(i, w->get(i));
  }
  *p = w->get(size);
}

#ifndef CHAR_WIDTH
#define CHAR_WIDTH 8
#endif

wire_value::wire_value(int size) {
  //assert(size > 0);
	bits = new char[size / CHAR_WIDTH]();
  len = size;
}

wire_value::~wire_value() {
	delete bits;
	bits = nullptr;
}

void wire_value::set(int i, bool b){
	//assert(i >= 0 && i < len);
	if(b){
		bits[i/CHAR_WIDTH] |= (1 << (i % CHAR_WIDTH));
	}
	else{
		bits[i/CHAR_WIDTH] &= ~(1 << (i % CHAR_WIDTH));
	}
}

bool wire_value::get(int i){
	//assert(i >= 0 && i < len);
	return (bits[i/CHAR_WIDTH] >> (i % CHAR_WIDTH)) & 1;
}

std::vector<char> wire_value::to_bytevec(){
  std::vector v;
  v.reserve(len*CHAR_WIDTH);
  v.assign(bits, bits + (len*CHAR_WIDTH));
  return v;
}

#include <openssl/sha.h>

//Output of SHA1 is 160 bits (20 bytes)
//#define SHA_OUTSIZE 20
wire_value * hash(wire_value * ka, wire_value * kb, int gate_number){
  std::vector<char> fullbuf;
  unsigned int numbits = ka->len + kb->len + sizeof(gate_number)*CHAR_WIDTH;
  fullbuf.reserve(numbits/CHAR_WIDTH);
  fullbuf.insert(fullbuf.end(), ka->bits, (ka->bits) + (ka->len/CHAR_WIDTH) + (ka->len % CHAR_WIDTH? 1 : 0));
  fullbuf.insert(fullbuf.end(), kb->bits, (kb->bits) + (kb->len/CHAR_WIDTH) + (kb->len % CHAR_WIDTH? 1 : 0));
  for(unsigned int i = 0; i < sizeof(gate_number); i++){
    fullbuf.push_back((gate_number >> (i*CHAR_WIDTH) & 0xFF));
  }
  wire_value * wv = new wire_value(SHA256_DIGEST_LENGTH*CHAR_WIDTH);
  SHA256(fullbuf.data(), fullbuf.size(), wv->bits);
  return wv;
}

bool hash(wire_value * ke, char * str, int gate_number){
  std::vector<char> fullbuf;
  unsigned int numbits = ke->len + strlen(str) + sizeof(gate_number)*CHAR_WIDTH;
  fullbuf.reserve(numbits/CHAR_WIDTH);
  fullbuf.insert(fullbuf.end(), ke.bits, (ke->bits) + (ke->len/CHAR_WIDTH) + (ke->len % CHAR_WIDTH? 1 : 0));
  fullbuf.insert(fullbuf.end(), str, strlen(str));
  for(unsigned int i = 0; i < sizeof(gate_number); i++){
    fullbuf.push_back((gate_number >> (i*CHAR_WIDTH) & 0xFF));
  }
  char hashout[SHA256_DIGEST_LENGTH];
  SHA256(fullbuf.data(), fullbuf.size(), hashout);
  return (hashout[0]) & 1;
}


wire_value * random_wire(int width){
	//assert(width > 0);
	wire_value * wv = new wire_value(width);
	for(int i = 0; i < width/CHAR_WIDTH; i++){
		wv[i] = rand() & 0xFF;
	}	
	return wv;
}	

bool random_bit(){
	return rand() & 1;	
}	


wire_value * xor_wire(wire_value * w1, wire_value * w2){
  int min_len = w1->len < w2->len ? w1->len : w2->len;
  wire_value * wv = new wire_value(min_len);
  int num_bytes = min_len/CHAR_WIDTH;
  if(min_len % CHAR_WIDTH){
    num_bytes++;  
  }
  for(int i = 0; i < num_bytes; i++){
    wv->bits[i] = w1->bits[i] ^ w2->bits[i];
  }
  return wv;
}



