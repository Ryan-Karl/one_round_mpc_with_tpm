#include <thread>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "garble_util.h"

using namespace std;

// Called by server.  Expects the structure of the circuit but not values relevant to garbling.
void get_garbled_circuit(Circuit * c, PlayerInfo ** players) {
  //Get randomness from player info
  wire_value * R = random_wire(c->security);
  for (Wire * i = c->input_wires[0]; i != NULL; i++) {
    i->p0 = random_bit();
    i->p1 = xor_bit(i->p0, constbit_1);
    i->k0 = random_wire(c->security);
    i->k1 = xor_wire(i->k0, R);
  }
  queue<Wire *> t_ordering;
  //TODO: get topological ordering
  while (!t_ordering.empty()) {
    Wire * w = t_ordering.pop();
    if (w->is_gate && w->gate_type == GATE_XOR) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;
      w->p0 = xor_bit(a->p0, b->p0);
      // This would work with xor_bit(a->p1,b->p1), as well as xor_bit(a->p0, b->p0),
      // it will always be the same value.
      w->p1 = xor_bit(constbit_1, w->p0);
      w->k0 = xor_wire(a->k0, b->k0);
      w->k1 = xor_wire(w->k0, R);
    } else if (w->is_gate) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;

      w->p0 = random_bit();
      w->p1 = xor_bit(i->p0, constbit_1);
      w->k0 = random_wire(c->security);
      w->k1 = xor_wire(i->k0, R);

      //va=0, vb=0
      bit out = eval_gate(w->gate_type, 0, 0);
      wire_value * w_out = wire2garbling(w, out);
      wire * e00 = xor_wire(w_out, hash(a->k0, b->k0, w->gate_number));
      //TODO do similarly for other wires, and find a way to do this as a loop
      //va=0, vb=1
      //va=1, vb=0
      //va=1, vb=1
    }
  }
  for (Wire * i = c->output_wires[0]; i != NULL; i++) {
    //TODO: create garbled output table
  }
  //TODO: do nested encryption of labels with finite use keys
  //   -- probably should abstract into another function.
}

// the garbling is just the concatenation of w->kb and w->pb for b=which
wire_value * wire2garbling(Wire * w, bit * which) {
  int size = w->size + 1;
  wire_value * ret = new wire_value(size);
}

int eval_garbled_circuit(Circuit * c, PlayerInfo * player) {
/*
[INCOMPLETE] pseudocode
compute
  if wire's connected to a gate root:
    if root is an XOR:
      label0 = assign_masks(left) xor assign_masks(right)
      label1 = label0 xor GETRAND
    if root is an AND:
  //Get
*/
}
