#ifndef GARBLE_UTIL_H
#define GARBLE_UTIL_H

#include <vector>
#include <deque>

//Should be able to be used for a general width sequence of bits
class wire_value {
  public:
  char * bits;
  int len;
  void set(int i, bool b);
  std::vector<char> to_bytevec()const ;
  bool get(int i) const ;
  void xor_with(wire_value * rhs);

  wire_value(int size);
  ~wire_value();
};


int p_to_int(bool p1, bool p0);

wire_value * xor_wire(wire_value * w1, wire_value * w2);

wire_value * random_wire(int width);
bool random_bit();
// Gives the hash of the concatenation of the below.  Must be of length (sec_param + 1)!
// (split into arguments for convenience, will likely need to be concatenated)
wire_value * hash_wire(wire_value * ka, wire_value * kb, int gate_number);
// For the final one.
bool hash_bool(wire_value * ke, char * str, int gate_number);
//wire_value * new_wire(int bitwidth);

typedef unsigned char gate_type;
// 11, 10, 01, 00   for xy
//  0   1   1   0 = 6 = 0x6 for XOR(x,y)
//  1   0   0   0 = 8 = 0x8 for AND(x,y)
//  1   1   0   0 = 12 = 0xc for GETX(x,y)
//  1   1   1   0 = 14 = 0xe for OR(x, y)
const gate_type GATE_XOR = 0x6;
bool eval_gate(gate_type g, bool x, bool y);

struct Wire {
  //p - permutation bit - p_0, p_1 correspond to p[0], p[1]
  bool p[2];
  //k - key bits - k_0, k_1 correspond to k[0], k[1]
  wire_value * k[2];

  int gate_number;

  // garbled label for the NIOT, at least for root nodes (before the nested encryption and such) // Only used when wire is a gate, and when gate is not XOR // corresponds to 00, 01, 10, 11
  bool garbled_labels[4];

  bool is_root;
  bool output_garble_info[2];
  bool output_value;

  // If this wire is the output of a gate, this section has useful information.
  bool is_gate;
  gate_type g_type;
  Wire * left_child;
  Wire * right_child;

  // Will likely be used only during execution, received from other players
  wire_value * label_kp;
  //Converted into these once received
  wire_value * label_k;
  bool label_p;
};

struct Circuit {
  std::vector<Wire *> output_wires;
  std::vector<Wire *> input_wires;
  // number of wires -- will be more than the number of gates
  long n_wires;
  // Security parameter
  int security;
};

//Garble circuit
void get_garbled_circuit(Circuit * c);
void top_sort(std::deque<Wire *> & destination, const Circuit * circuit);


#endif
