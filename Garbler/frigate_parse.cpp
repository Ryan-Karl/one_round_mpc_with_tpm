#include "player.h"
#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <cassert>

/*  test function
int main(int argc, char ** argv) {
  Circuit c;
  std::vector<PlayerInfo *> players(10);
  for (int i =0; i<10;i++) players[i] = new PlayerInfo;
  int security = 20;
  read_frigate_circuit(argv[1], &c, players, security);
}
*/

void expand_add(std::vector<Wire*> *wires, int index, Wire * w) {
	if (wires->size() <= index) {
		wires->resize(index + 1, nullptr);
	}
	(*wires)[index] = w;
}

void read_frigate_circuit(char * filename, Circuit * circuit, std::vector<PlayerInfo *> * players, int security) {
	circuit->security = security;
	//associates number to Wire
	std::vector<Wire *> wires;
	std::ifstream file(filename);
	if (!file.good())
		exit(1);
	std::string in;
	std::string out;
	int max_player = 0;
	int n_wires = 0;
	int wire_i, player;
	while (file.peek() == 'I') {
		file >> in >> wire_i >> player;
		//DEBUGGING
		//std::cout << in << ' ' << wire_i << ' ' << player << std::endl;
		//0/1-based indexing
		/*
		assert(player);
		player--;
		*/
		assert(player >= 0);

		file.ignore(); // ignore \n
		Wire * w = new Wire;
		w->gate_number = wire_i;
		w->is_root = false;
		w->is_gate = false;
		assert(wire_i >= wires.size() || wires[wire_i] == nullptr);
		expand_add(&wires, wire_i, w);
		circuit->input_wires.push_back(w);
		(*players)[player]->input_wires.push_back(w);
		max_player = std::max(max_player, player);
		n_wires += 1;
	}
	int x, y;
	int gatenum;
	while (file.peek() != 'O') {
		if (file.peek() == 'c') {
			file.ignore(5); //ignore copy(
			file >> gatenum;
			file.ignore(1); //ignore )
			file >> wire_i >> x >> y;
		}
		else {
			file >> gatenum >> wire_i >> x >> y;
		}
		file.ignore(); // ignore \n
		//DEBUGGING
		//std::cout << gatenum << ' ' << wire_i << ' ' << x << ' ' << y << std::endl;
		Wire * w;
		if (wire_i >= wires.size() || wires[wire_i] == nullptr) {
			w = new Wire;
			expand_add(&wires, wire_i, w);
		}
		else {
			w = wires[wire_i];
		}
		w->gate_number = wire_i;
		w->is_gate = true;
		w->g_type = (gate_type)gatenum;
		if (x >= wires.size() || wires[x] == nullptr) {
			Wire * x_ptr = new Wire;
			expand_add(&wires, x, x_ptr);
		}
		w->left_child = wires[x];
		if (y >= wires.size() || wires[y] == nullptr) {
			Wire * y_ptr = new Wire;
			expand_add(&wires, y, y_ptr);
		}
		w->right_child = wires[y];
		expand_add(&wires, wire_i, w);
		n_wires += 1;
	}
	while (file.peek() == 'O') {
		// Note -- ignores which player an output wire is 'for'
		file >> out >> x >> player;
		if (x >= wires.size() || wires[x] == nullptr) {
			Wire * x_ptr = new Wire;
			expand_add(&wires, x, x_ptr);
		}
		wires[x]->is_root = true;
		circuit->output_wires.push_back(wires[x]);
		file.ignore(); // ignore \n
	}
	circuit->n_wires = n_wires;
}
