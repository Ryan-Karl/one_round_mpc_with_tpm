#include "garble_util.h"
#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char ** argv) {
  read_frigate_circuit(argv[1], NULL);
}

void read_frigate_circuit(char * filename, Circuit * circuit) {
  std::ifstream file(filename);
  if (!file.good())
    exit(1);
  std::string in;
  std::string out;
  int max_player=0;
  int wire, player;
  while (file.peek() == 'I') {
    file >> in >> wire >> player;
    wires[wire]
    file.ignore();
  }
  int x, y;
  int f;
  int g;
  while (file.peek() != 'O') {
    if (file.peek() == 'c') {
      file.ignore(5);
      file >> x;
      file.ignore(1);
      file >> y >> g >> f;
      std::cout << "copy(" << x << ") " << y << " " << g << " " << f << "\n";
    } else {
      file >> x >> y >> g >> f;
      std::cout << x << " " << y << " " << g << " " << f << "\n";
    }
    file.ignore();
  }
  while (file.peek() == 'O') {
    file >> out >> x >> y;
    std::cout << x << " " << y << "\n";
    file.ignore();
  }
}
