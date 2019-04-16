// (at least) 64 bits -- is this the best way?
typedef bit_wire unsigned long long;
typedef bit bool;

void get_garbled_circuit(Circuit * c, PlayerInfo ** players);
int eval_garbled_circuit(Circuit * c, PlayerInfo * player);

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
  bit_wire k0;
  bit p1;
  bit_wire k1;

  // garbled label for the NIOT, at least for root nodes (before the nested encryption and such)
  bit garbled_label;

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
  bit_wire value;
} Wire;

typedef struct {
  Wire ** output_wires;
  Wire ** input_wires;
  long n_gates;
} Circuit;

