# One Round MPC With TPM

Microsoft Instructions 
================================================

Download Visual Studio from https://visualstudio.microsoft.com/downloads/

Double click simulator app downloaded from https://www.microsoft.com/en-us/download/details.aspx?id=52507&from=http%3A%2F%2Fresearch.microsoft.com%2Fen-us%2Fdownloads%2F35116857-e544-4003-8e7b-584182dc6833%2Fdefault.aspx.

Double click on ...\GitHub\TSS.MSR\TSS.CPP\Src\TSS>CPP.sln

Click okay to various prompts in Visual Studio and eventually click Build->Build Solution in upper dropdown menu.

May need to download .NET 4.6 framework.

May need to right click Samples.cpp and set as StartUp Project.

Notes on Frigate Circuits:
----------------------------------------------------------------

flags:
 -i           run interpreter after compilation
 -i_io        see interpreter input and output (requires -i)
 -i_output [file]	prints out gates and input output (copies are replaced with XORs with 0 as second operand) file (requires -i)


Example uses of Frigate:
---------------------------------------------------------------
./frigate ./tests/temp.wir -i
->>>> this compiles temp.wir, runs it with the interpreter

./frigate ./tests/temp.wir -i_output out -i
->>>> this compiles temp.wir, runs it with the interpreter and outputs the circuit to file “out”

./frigate ./tests/temp.wir -i -i_io
->>>> this compiles temp.wir, runs it with the interpreter and prints out the output

flag: -i_output out -i     [-i is required with -i_output]

output: (cat’d from file “out”)


IN 0 1

IN 1 1
...

15 16 0 0

0 17 0 0

6 25 26 18
...

copy(6) 7 25 17
...

OUT 7 1


IN 3 1 -> input next bit from party 1 to wire 3

Interpret line 8 21 19 0 as, take inputs (from wires) 19 and 0, use truth table 8, and output to wire 21. 

“truth table 8” refers to the truth table output values represented as a integer (8). 8 = output_00 | output_01 < 2 | output_10 < 3 | output_11 << 3. 

In other words 8 is an AND gate, 6 is an XOR gate, 14 is an OR gate, 15 always returns 1 no matter the inputs, and 0 always returns 0 no matter the inputs.

copy(6) 4 19 17 -> copies whats on wire 19 to wire 4.

OUT 4 1 -> output whats on wire 4 to party 1

