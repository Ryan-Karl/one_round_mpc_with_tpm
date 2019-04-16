#include <thread>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;

//Called by server
void get_garbled_circuit(Circuit * c, PlayerInfo ** players) {
  //Get randomness from player info

/*
[INCOMPLETE] pseudocode
assign_masks(wire):
  R = newRAND(N)
  For all input wires i (i.e. leaves):
    //Permutation bit, key
    p0 = newRANDbit
    k0 = newRAND(N)
    p1 = p0 ^ 1
    k1 = k0 ^ R
    w0 = k0 ++ p0
    w1 = k1 ++ p1
  For each gate in topological with inputs a, b:
*/

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
