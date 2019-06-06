#!/usr/bin/python

import argparse, random

# initiate the parser
parser = argparse.ArgumentParser()

# add long and short argument
parser.add_argument("--parties", "-p", help="set party number")
parser.add_argument("--depth", "-d", help="set depth")
parser.add_argument("--XOR", "-x", help="set XOR percentage")

# read arguments from the command line
args = parser.parse_args()

parties_input = int(args.parties)
levels_input = int(args.depth)
percent_XOR = int(args.XOR)

val = 0
num = parties_input
circuit_range = {}
party_id = 0
increment = round((2**(levels_input - 1))/parties_input)

while val < levels_input:
    circuit_range[val] = list(range( 2 ** (val) - 1, (2 ** (val + 1) - 1)))
    val += 1

while num > 0:
    for k in circuit_range[levels_input-1]:
        if (k >= ((2**(levels_input - 1) - 1) + (party_id * increment))) and (k < ((2**(levels_input - 1) - 1) + ((party_id + 1) * increment))):
            print("IN " + str(k) + " " + str(party_id))

    party_id += 1
    num -= 1

q = levels_input - 1
while q > 0:
    s = 0
    for i in circuit_range[q][::2]:
        rand_num = random.randrange(100)
        if(rand_num >= percent_XOR):
            print("8 " + str(circuit_range[q-1][s]) + " " + str(i) + " " + str(i + 1))
        else:
            print("6 " + str(circuit_range[q-1][s]) + " " + str(i) + " " + str(i + 1))

        s+=1
    q-=1

print("OUT 0 0")
