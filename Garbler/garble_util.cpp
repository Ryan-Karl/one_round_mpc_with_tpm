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
    bit p0 = random_bit();
    bit p1 = xor_bit(p0, constbit_1);
    wire_value * k0 = random_wire(c->security);
    wire_value * k1 = xor_wire(k0, R);

    i->p0 = p0;
    i->p1 = p1;
    i->k0 = k0;
    i->k1 = k1;
  }
  queue<Wire *> t_ordering;
  //TODO: get topological ordering
  while (!t_ordering.empty()) {
    Wire * w = t_ordering.pop();
    if (w->is_gate && w->gate_type == GATE_XOR) {
      //TODO
    } else if (w->is_gate) {
      //TODO
    }
  }
  for (Wire * i = c->output_wires[0]; i != NULL; i++) {
    //TODO: create garbled output table
  }
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
