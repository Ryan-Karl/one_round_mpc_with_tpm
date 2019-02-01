# one_round_mpc_with_tpm

How to install:
Download from https://sourceforge.net/projects/ibmtpm20tss/ and https://sourceforge.net/projects/ibmswtpm2/
Use tar xvf to unzip.

sudo apt-get install openssl libssl-dev apache2 apache2-dev php php-dev libapache2-mod-php

sudo mkdir /var/www/html/tpm2

sudo chmod 777 /var/www/html/tpm2

sudo mkdir /dev/tpm0

sudo chmod 777 /dev/tpm0


For TPM:
“cd” into “src” subdirectory of tpm directory and enter “make” (about 1 minute).

Run command “./tpm_server”

In seperate terminal, for TSS:

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

