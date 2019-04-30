#ifndef PLAYER_H
#define PLAYER_H

#include "garble_util.h"
#include <vector>

typedef struct {
  // input_wires are the wires belonging to this player
  std::vector<Wire *> input_wires;
} PlayerInfo;

#endif
