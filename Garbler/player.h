#include "garble_util.h"

typedef struct {
  //Should there be networking info here?

  //Should this be a bytevec?
  char * TPM_pubkey;
  // input_wires are the wires belonging to this player
  vector<Wire *> input_wires;
} PlayerInfo;
