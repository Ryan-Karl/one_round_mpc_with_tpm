//LIKELY UNUSUED -- duplicated functionality
#include "encryption_util.h"
#include "garble_util.h"
#include "player.h"
#include "TPMWrapper.h"

// Does nested encryption of input labels to prevent residual function attack.
vector<???> NIMPC_garble(Circuit * c, vector<PlayerInfo *> players) {
  get_garbled_circuit(c);
  //for every player with n input wires and public key k
  for (auto it = players.begin(); it < players.end(); it++) {
    int n = (*it)->input_wires.length();
    int width = c->security;
    vector<wire_value *> masks(n);
    wire_value * R = wire_value(width);
    //select n partial keys of bit width security param, let R be the xor of them all.
    for (int i=0;i<n;i++) {
      masks[i] = random_wire(width);
      R->xor_with(masks[i]);
    }
    //for every input wire w of player
    for (auto w_it=(*it)->input_wires.begin();w_it<(*it)->input_wires.end();w_it++) {
      TPMWrapper::s_RSA_encrypt
      //c0 = pk_k(sk_R(x0), R_w)
      //c1 = pk_k(sk_R(x1), R_w)
    }
  }
}

vector<???> NIMPC_choice( ??? ) {
}
