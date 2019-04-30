#ifndef PLAYER_H
#define PLAYER_H

#include "garble_util.h"
#include <vector>

typedef struct {
  // input_wires are the wires belonging to this player
  std::vector<Wire *> input_wires;
} PlayerInfo;

//Read frigate circuit and parse into structure -- called by server
void read_frigate_circuit(char * filename, Circuit * circuit, std::vector<PlayerInfo *> players, int security);

#endif
