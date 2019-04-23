#include "garble_util.h"

// Does nested encryption of input labels to prevent residual function attack.
void NIMPC_garble(Circuit * c, PlayerInfo ** players) {
  get_garbled_circuit(c);
  //for every player with n input wires and public key k
    //select n partial keys of bit width security param, let R be the xor of them all.
    //for every input wire w of player
      //c0 = pk_k(sk_R(x0), R_w)
      //c1 = pk_k(sk_R(x1), R_w)
}
