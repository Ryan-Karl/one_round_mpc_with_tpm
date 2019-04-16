// (at least) 64 bits -- is this the best way?
//Should be able to be used for a general width sequence of bits
typedef struct {
  char * bits;
  int len;
} wire_value;

typedef bool bit;
const bit constbit_1 = true;
const bit constbit_0 = false;

void get_garbled_circuit(Circuit * c, PlayerInfo ** players);
int eval_garbled_circuit(Circuit * c, PlayerInfo * player);

wire_value * xor_wire(wire_value * w1, wire_value * w2);
// xor_bit can of course be done without this concisely but just in case representation changes it will be nice to be able to abstract away
bit xor_bit(bit b1, bit b2);

wire_value * random_wire(int width);
bit random_bit();
bit hash(wire * ka, wire * kb, int gate_number);

//Read frigate circuit and parse into structure
void read_frigate_circuit(char * filename, Circuit * circuit);

typedef struct {
  // Shared in setup
  char * randomness_file;
  char * host;
  char * port;
  //Should this be a bytevec?
  char * TPM_pubkey;
} PlayerInfo;

typedef enum gate_type {
  GATE_XOR,
  GATE_AND,
  // Constant 0 gate
  GATE_C0,
  // Constant 1 gate
  GATE_C1
} gate_type;

typedef struct {
  //p - permutation bit
  bit p0;
  //k - key bits
  wire_value * k0;
  bit p1;
  wire_value * k1;

  int gate_number;

  // garbled label for the NIOT, at least for root nodes (before the nested encryption and such)
  // Only used when wire is a gate, and when gate is not XOR
  bit garbled_label_00;
  bit garbled_label_01;
  bit garbled_label_10;
  bit garbled_label_11;

  bool is_root;

  // If this is a leaf node, player has useful information.
  bool is_leaf;
  PlayerInfo * player;

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
