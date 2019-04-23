#ifndef GARBLE_UTIL_H
#define GARBLE_UTIL_H
// (at least) 64 bits -- is this the best way?
//Should be able to be used for a general width sequence of bits
class wire_value {
  public:
  char * bits;
  int len;
  set(int i);
  unset(int i);
};

wire_value::wire_value(int size);
wire_value::~wire_value();

typedef bool bit;
const bit constbit_1 = true;
const bit constbit_0 = false;

void get_garbled_circuit(Circuit * c);

wire_value * xor_wire(wire_value * w1, wire_value * w2);
// xor_bit can of course be done without this concisely but just in case representation changes it will be nice to be able to abstract away
bit xor_bit(bit b1, bit b2);

wire_value * random_wire(int width);
bit random_bit();
// Gives the hash of the concatenation of the below.  Must be of length (sec_param + 1)!
// (split into arguments for convenience, will likely need to be concatenated)
wire_value * hash(wire_value * ka, wire_value * kb, int gate_number);
// For the final one.
wire_value * hash(wire_value * ke, char * str, int gate_number);
//wire_value * new_wire(int bitwidth);

//Read frigate circuit and parse into structure
void read_frigate_circuit(char * filename, Circuit * circuit);

//TODO: numbering
typedef enum gate_type {
  GATE_XOR,
  GATE_AND,
  // Constant 0 gate
  GATE_C0,
  // Constant 1 gate
  GATE_C1
} gate_type;

typedef struct {
  //p - permutation bit - p_0, p_1 correspond to p[0], p[1]
  bit p[2];
  //k - key bits - k_0, k_1 correspond to k[0], k[1]
  wire_value * k[2];

  int gate_number;

  // garbled label for the NIOT, at least for root nodes (before the nested encryption and such)
  // Only used when wire is a gate, and when gate is not XOR
  // corresponds to 00, 01, 10, 11
  bit garbled_labels[4];

  bool is_root;
  bit output_garble_info[2];
  bit output_e0;
  bit output_e1;

  // If this wire is the output of a gate, this section has useful information.
  bool is_gate;
  gate_type g_type;
  Wire * left_child;
  Wire * right_child;

  // Will likely be used only during execution
  wire_value value;
} Wire;

typedef struct {
  // Null terminated array of pointers to output (resp. input) wires
  Wire ** output_wires;
  Wire ** input_wires;
  long n_gates;
  // Security parameter
  int security;
} Circuit;

#endif
