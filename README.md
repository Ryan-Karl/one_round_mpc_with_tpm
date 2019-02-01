# one_round_mpc_with_tpm

How to install TPM:
---------------------------------------------------
Download from https://sourceforge.net/projects/ibmtpm20tss/ and https://sourceforge.net/projects/ibmswtpm2/
Use tar xvf to unzip.

sudo apt-get install openssl libssl-dev apache2 apache2-dev php php-dev libapache2-mod-php

sudo mkdir /var/www/html/tpm2

sudo chmod 777 /var/www/html/tpm2

sudo mkdir /dev/tpm0

sudo chmod 777 /dev/tpm0


For TPM:
------------------------------------------------------
“cd” into “src” subdirectory of tpm directory and enter “make” (about 1 minute).

Run command “./tpm_server”


In seperate terminal, for TSS:
------------------------------------------------------
"cd" into "utils" subdirectory of tss directory and enter "make" (about 1 minute).

run commmand "./reg.sh –a" (should recieve success message for 31 tests after 2-3 minutes but on first run may encounter errors)

"cd" into "demo" subdirectory of tss directory and enter "make".

In “utils” subdirectory of tss directory run “./powerup” and “./startup”. 

sudo systemctl restart apache2

sudo ufw allow 80

In “utils” subdirectory of tss directory run “./powerup” and “./startup”. 

Use Firefox to navigate to http://localhost/tpm2/index.php 

May need to run "service httpd start" or "service httpd restart" if there is trouble connecting to the server.

This will give you access to a GUI framework that demonstrates its core functionality (we are interested in generating keys and the nv indexes).


Example TPM Program
---------------------------------------------------------
The signapp.c source shows how several commands can be chained together to form an
application. It does the following:
> Start an authorization HMAC session
> Create a primary storage key, using the session
> Create a signing key under the storage key
> Load the signing key, using the session
> Sign a digest, using the session
> Verify the signature
> Flush the primary key
> Flush the signing key
> Flush the session


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

