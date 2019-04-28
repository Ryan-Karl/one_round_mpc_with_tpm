#include <thread>
#include <math.h>
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
    w->p[1] = xor_bit(w->p[0], constbit_1);
    w->k[0] = random_wire(c->security);
    w->k[1] = xor_wire(w->k[0], R);
  }
  queue<Wire *> t_ordering;
  //TODO: get topological ordering
  while (!t_ordering.empty()) {
    Wire * w = t_ordering.pop();
    if (w->is_gate && w->gate_type == GATE_XOR) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;
      w->p[0] = xor_bit(a->p[0], b->p[0]);
      // This would work with xor_bit(a->p1,b->p1), as well as xor_bit(a->p0, b->p0),
      // it will always be the same value.
      w->p[1] = xor_bit(constbit_1, w->p[0]);
      w->k[0] = xor_wire(a->k[0], b->k[0]);
      w->k[1] = xor_wire(w->k[0], R);
    } else if (w->is_gate) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;

      w->p[0] = random_bit();
      w->p[1] = xor_bit(i->p[0], constbit_1);
      w->k[0] = random_wire(c->security);
      w->k[1] = xor_wire(i->k[0], R);

      for (int i_a=0;i_a<=1;i_a++) {
        for (int i_b=0;i_b<=1;i_b++) {
          bit out = eval_gate(w->gate_type, i_a, i_b);
          wire_value * w_out = wire2garbling(w, out);
          wire * e = xor_wire(w_out, hash(a->k[i_a], b->k[i_b], w->gate_number));
          int index = 2 * bit_to_int(a->p[i_a]) + bit_to_int(b->p[i_b]);
          w->garbled_labels[index] = e;
        }
      }
    }
  }

  // create garbled output tables
  for (auto w_it = c->output_wires.begin(); w_it<c->output_wires.end(); w++) {
    Wire * w = *w_it;
    bit * e0 = xor_bit(constbit_0, hash(w->k[0], "out", w->gate_number));
    bit * e1 = xor_bit(constbit_1, hash(w->k[1], "out", w->gate_number));
    w->output_garble_info[bit_to_int(w->p[0])] = e0;
    w->output_garble_info[bit_to_int(w->p[1])] = e1;
  }
}

void eval_garbled_circuit(ClientCircuit * c) {
  //TODO convert base labels from kp to k, p
  queue<Wire *> t_ordering;
  //TODO: get topological ordering, probably use a function from before
  while (!t_ordering.empty()) {
    Wire * w = t_ordering.pop();
    if (w->is_gate && w->gate_type == GATE_XOR) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;
      w->label_p = xor_bit(a->label_p, b->label_p);
      w->label_k = xor_wire(a->label_k, b->label_k);
    } else if (w->is_gate) {
      Wire * a = w->left_child;
      Wire * b = w->right_child;
      int index = 2 * bit_to_int(a->label_p) + bit_to_int(b->label_p);
      wire_value * garbling = xor_wire(w->garbled_labels[index], hash(a->label_k, b->label_k, w->gate_number));
      garbling2wire(garbling, w->label_k, w->label_p);
    }
  }
  for (auto w_it = c->output_wires.begin(); w_it<c->output_wires.end(); w++) {
    Wire * w = *w_it;
    bit * out = xor_bit(w->output_garble_info[bit_to_int(w->label_p)], hash(w->label_k, "out", w->gate_number));
  }
}

// the garbling is just the concatenation of w->kb and w->pb for b=which
wire_value * wire2garbling(const Wire * w, const bit * which) {
  wire_value * k = w->k[bit_to_int(which)]
  int size = k->size + 1;
  wire_value * ret = new wire_value(size);
  for (int i = 0; i < size - 1; i++) {
    ret->set(i, k->get(i));
  }
  ret->set(size-1, w->p[bit_to_int(which)]->get(i));
  return ret;
}

void garbling2wire(const wire_value *w, wire_value *k, bit *p) {
  int size = w->size - 1;
  for (int i = 0; i < size; i++) {
    k->set(i, w->get(i));
  }
  *p = w->get(size);
}
