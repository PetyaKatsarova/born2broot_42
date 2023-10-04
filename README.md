sudo# born2broot_42
copied info from: https://github.com/pasqualerossi/Born2BeRoot-Guide/blob/main/README.md


AppArmor is a security framework in Debian that allows for the confinement of processes to specific resources, such as files or network sockets, in order to limit their potential for causing harm. It provides an additional layer of security to the operating system by defining and enforcing policies that restrict the actions that processes can take, thereby reducing the risk of security vulnerabilities being exploited.


**************** # **CONFIG THE VM** ************************

Part 4.1 - Installing Sudo

su - to login in as the root user

apt-get update -y

apt-get upgrade -y

apt install sudo

usermod -aG sudo your_username to add user in the sudo group (To check if user is in sudo group, type getent group sudo)

sudo visudo to open sudoers file

find - # User privilege specification, type your_username      ALL=(ALL) ALL

************* #Installing and Configuring SSH (Secure Shell Host) *************** 

Type sudo apt install openssh-server
Type sudo systemctl status ssh to check SSH Server Status
Type sudo vim /etc/ssh/sshd_config
Find this line #Port22
Change the line to Port 4242 without the # (Hash) in front of it
Save and Exit Vim
Then type sudo grep Port /etc/ssh/sshd_config to check if the port settings are right
Lastly type sudo service ssh restart to restart the SSH Service

************* Installing and Configuring UFW (Uncomplicated Firewall) ************

First type apt-get install ufw to install UFW
sudo ufw enable to inable UFW
sudo ufw status numbered to check the status of UFW
sudo ufw allow ssh to configure the Rules
sudo ufw allow 4242 to configure the Port Rules
Lastly Type sudo ufw status numbered // to check the status of UFW 4242 Port

*********** Connecting to SSH ********

Click on your Virtual Machine and select Settings
Click Network then Adapter 1 then Advanced and then click on Port Forwarding
Change the Host Port and Guest Port to 4242
Then head back to your Virtual Machine
sudo systemctl restart ssh to restart your SSH Server
sudo service sshd status to check your SSH Status
Open an iTerm and type the following ssh your_username@127.0.0.1 -p 4242
In case an error occurs, then type rm ~/.ssh/known_hosts in your iTerm and then retype ssh your_username@127.0.0.1 -p 4242
Lastly type exit to quit your SSH iTerm Connection

****** Setting up password policy ************* 

Fisudo apt-get install libpam-pwquality //install Password Quality Checking Library
sudo vim /etc/pam.d/common-password
Find this line. password        requisite        pam_deny.so
 The line should now look like this - password  requisite     pam_pwquality.so  retry=3 minlen=10 ucredit=-1 dcredit=-1 maxrepeat=3 reject_username difok=7 enforce_for_root
 Save and Exit Vim
 sudo vim /etc/login.defs
 Find this part PASS_MAX_DAYS 9999 PASS_MIN_DAYS 0 PASS_WARN_AGE 7
 Change that part to PASS_MAX_DAYS 30 and PASS_MIN_DAYS 2 keep PASS_WARN_AGE 7 as the same
 sudo reboot // reboot the change affects
 // change password:
 sudo passwd pkatsaro
     sudo chage -l username - check password expire rulessudo
 
 ********* Creating a Group ************** 
 
sudo groupadd user42 //  create a group
 sudo groupadd evaluating // create an evaluating group
 getent group // check if the group has been created

******* Greating User and Assigning to a gr ***********

cut -d: -f1 /etc/passwd // check all local users
sudo adduser new_username // create a username 
sudo usermod -aG user42 your_username
 sudo usermod -aG evaluating your_new_username
 getent group user42 // check if the user is the group
 getent group evaluating // check the group
groups // to see which groups the user account belongs to
chage -l your_new_username // to check if the password rules are working in users

********* Creating sudo.log ************

cd /var/log
Then type mkdir sudo (if it already exists, then continue to the next step).
Then type cd sudo && touch sudo.log

******** Config Sudoers Gr ********

First type sudo nano /etc/sudoers to go the sudoers file
Now edit your sudoers file to look like the following by adding in all of the defaults
Defaults    env_reset
Defaults    mail_badpass
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/bin:/sbin:/bin"
Defaults    badpass_message="Password is wrong, please try again!"
Defaults    passwd_tries=3
Defaults    logfile="/var/log/sudo/sudo.log"
Defaults    log_input, log_output
Defaults    requiretty

******* Crontab config *********
to escape broadcast: ctlr+L

Then type apt-get install -y net-tools to install the netstat tools
Then type cd /usr/local/bin/
Then type touch monitoring.sh
Lastly type chmod 777 monitoring.sh
the text bellow is the script: 

#!/bin/bash
arc=$(uname -a)
pcpu=$(grep "physical id" /proc/cpuinfo | sort | uniq | wc -l) 
vcpu=$(grep "^processor" /proc/cpuinfo | wc -l)
fram=$(free -m | awk '$1 == "Mem:" {print $2}')
uram=$(free -m | awk '$1 == "Mem:" {print $3}')
pram=$(free | awk '$1 == "Mem:" {printf("%.2f"), $3/$2*100}')
fdisk=$(df -BG | grep '^/dev/' | grep -v '/boot$' | awk '{ft += $2} END {print ft}')
udisk=$(df -BM | grep '^/dev/' | grep -v '/boot$' | awk '{ut += $3} END {print ut}')
pdisk=$(df -BM | grep '^/dev/' | grep -v '/boot$' | awk '{ut += $3} {ft+= $2} END {printf("%d"), ut/ft*100}')
cpul=$(top -bn1 | grep '^%Cpu' | cut -c 9- | xargs | awk '{printf("%.1f%%"), $1 + $3}')
lb=$(who -b | awk '$1 == "system" {print $3 " " $4}')
lvmu=$(if [ $(lsblk | grep "lvm" | wc -l) -eq 0 ]; then echo no; else echo yes; fi)
ctcp=$(ss -neopt state established | wc -l)
ulog=$(users | wc -w)
ip=$(hostname -I)
mac=$(ip link show | grep "ether" | awk '{print $2}')
cmds=$(journalctl _COMM=sudo | grep COMMAND | wc -l)
wall "    #Architecture: $arc
    #CPU physical: $pcpu
    #vCPU: $vcpu
    #Memory Usage: $uram/${fram}MB ($pram%)
    #Disk Usage: $udisk/${fdisk}Gb ($pdisk%)
    #CPU load: $cpul
    #Last boot: $lb
    #LVM use: $lvmu
    #Connections TCP: $ctcp ESTABLISHED
    #User log: $ulog
    #Network: IP $ip ($mac)
    #Sudo: $cmds cmd"
    
    Then open up a iTerm2 seperate from your Virtual Machine and type in iTerm ssh your_host_name42@127.0.0.1 -p 4242 and then type your password, when it asks for it.
    Then type cd /usr/local/bin.
    Then type nano monitoring.sh and paste the text above into the vim monitoring.sh you just created, by doing command + v on your Apple keyboard.
    Save and Exit your monitoring.sh
    5.1 - Then type exit to exit the iTerm SSH Login.
    5.2 - Then go back to your Virtual Machine (not iTerm) and continue on with the steps below.
    Then type sudo visudo to open your sudoers file
    Add in this line your_username ALL=(ALL) NOPASSWD: /usr/local/bin/monitoring.sh under where its written %sudo ALL=(ALL:ALL) ALL
    
    Then exit and save your sudoers file
    Now type sudo reboot in your Virtual Machine to reboot sudo
    Type sudo /usr/local/bin/monitoring.sh to execute your script as su (super user)
    Type sudo crontab -u root -e to open the crontab and add the rule
    Lastly at the end of the crontab, type the following
    @reboot /bin/sh -c "sleep 20 && /full/path/to/your/script.shcao    
    */10 * * * * /usr/local/bin/monitoring.sh this means that every 10 mins, this script will show
    
    ****** Signature.txt ******
 
 close the machine.
 cd sgoinfre/students/<your_intra_username>/VirtualBox VMs
Type shasum yourdiskname.vdi or whatever your Virtual Machine is called (This can take from a few seconds to 5 mins).
Copy the output number and create a signature.txt file and paste that number in the file.
Now you submit the signature.txt file with the output number in it.
    
    ****** REFERENCE COMMANDS: ********
    
    sudo ufw status
    sudo systemctl status ssh
    getent group sudo
    getent group user42
    getent passwd {1000..60000}

    sudo groupadd groupname
    sudo usermod -aG groupname username
    sudo chage -l username - check password expire rules
    hostnamectl
    hostnamectl set-hostname new_hostname - to change the current hostname
    Restart your Virtual Machine.
    sudo nano /etc/hosts - change current hostname to new hostname
    lsblk to display the partitions
    dpkg -l | grep sudo – to show that sudo is installed
    sudo ufw status numbered
    // same as above: sudo /usr/sbin/ufw status
    sudo ufw allow port-id
    sudo ufw delete rule number
    ssh your_user_id@127.0.0.1 -p 4242 - do this in terminal to show that SSH to port 4242 is working
    // check sudo.log
    sudo cat /var/log/sudo/sudo.log
    // change password: 
    sudo passwd username
    // sudoers is in 
    // location of the bash script for crontab: /usr/local/bin/monitoring.sh   
    clear //for leaving the crontab message on the terminal
    //check os: 
    head -n 2 /etc/os-release
    
    // switch to different account
    su other_user // enter passwd for other user
    
// bonus

You can uninstall all the listed packages by running the following command as root:

apt-get remove mariadb-client-10.5 mariadb-common mariadb-server-10.5
If you also want to remove the configuration files for these packages, run the following command instead:

apt-get remove --purge mariadb-client-10.5 mariadb-common mariadb-server-10.5
This will remove the packages and their configuration files, but will not remove the data files stored in the databases. To remove the data files, you will need to manually delete the directories in which they are stored.

pskpetya@gmail.com
how to check if i have uninstalled lighttpd
To check if you have uninstalled Lighttpd on Debian, you can use the following command:

dpkg -l | grep lighttpd
This will return information about all installed packages that have the word "lighttpd" in their name. If Lighttpd is not installed, the command will return an empty result. You can also check the Lighttpd service status using the following command:

systemctl status lighttpd
This should return a message indicating that the service is not found, indicating that Lighttpd has been successfully uninstalled.


pskpetya@gmail.com
how to uninstall those: ii  lighttpd                       1.4.59-1+deb11u2               amd64        fast webserver with minimal memory footprint
ii  lighttpd-mod-deflate           1.4.59-1+deb11u2               amd64        HTTP response compression module for lighttpd
ii  lighttpd-mod-openssl           1.4.59-1+deb11u2               amd64        TLS support using OpenSSL module for lighttpd
To uninstall Lighttpd and its related packages in Debian, you can use the following command:

sudo apt-get remove lighttpd lighttpd-mod-deflate lighttpd-mod-openssl
This will remove the Lighttpd web server, the mod_deflate module for HTTP response compression, and the mod_openssl module for TLS support. Note that apt-get remove only removes the packages, but retains the configuration files. If you want to remove both the packages and their configuration files, you can use the purge option:

sudo apt-get remove --purge lighttpd lighttpd-mod-deflate lighttpd-mod-openssl



pskpetya@gmail.com
whats the command to check if apache is installed on my debian
You can use the following command to check if Apache is installed on your Debian system:

dpkg -l | grep apache2
If Apache is installed, you will see output similar to this:

Copy code
ii  apache2                         2.4.25-3+deb9u7                amd64        Apache HTTP Server
If you don't see any output, then Apache is not installed on your system.

pskpetya@gmail.com
how to uninstall apache2 and dependencies
To uninstall Apache2 and its dependencies on Debian, you can use the following command:

sudo apt-get remove apache2
This command will remove Apache2 and its associated packages, but it will not remove the configuration files or any data stored in the web root directory. If you want to completely remove Apache2, including its configuration files, you can use the following command instead:

sudo apt-get --purge remove apache2
Note: Before uninstalling Apache2, make sure that there is no critical data stored in the web root directory or in the Apache configuration files. It's always a good idea to backup any important data before making changes to your system.




pskpetya@gmail.com
how to uninstall those: ii  apache2-bin                    2.4.54-1~deb11u1               amd64        Apache HTTP Server (modules and other binary files)
ii  libapache2-mod-php7.4          7.4.33-1+deb11u1               amd64        server-side, HTML-embedded scripting language (Apache 2 module)
To uninstall Apache2 and its dependencies on Debian, you can use the following command:

sudo apt-get remove apache2-bin libapache2-mod-php7.4
This will remove the Apache2 binary package (apache2-bin) and the libapache2-mod-php7.4 package. You can also use the purge option instead of remove to remove the configuration files as well:

sudo apt-get purge apache2-bin libapache2-mod-php7.4



pskpetya@gmail.com
how to set up on my vm on debian: • Set up a functional WordPress website with the following services: lighttpd, MariaDB, and PHP. 
To set up a functional WordPress website with lighttpd, MariaDB, and PHP on a Debian-based system, you can follow these steps:

Install lighttpd, MariaDB, and PHP:
sql
Copy code
sudo apt-get update
sudo apt-get install lighttpd mariadb-server mariadb-client php7.4-fpm php7.4-mysql
Start and enable the lighttpd and mariadb services:
bash
Copy code
sudo systemctl start lighttpd
sudo systemctl enable lighttpd
sudo systemctl start mariadb
sudo systemctl enable mariadb
Secure the MariaDB installation:
Copy code
sudo mysql_secure_installation
Create a database and a user for WordPress:
css
Copy code
sudo mysql -u root -p
sql
Copy code
CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;
CREATE USER 'wpuser'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
Download and extract the latest version of WordPress:

wget https://wordpress.org/latest.tar.gz
tar -xzvf latest.tar.gz
Copy the extracted files to the document root directory of lighttpd:

sudo cp -r wordpress /var/www/html/
sudo chown -R www-data:www-data /var/www/html/wordpress
Configure lighttpd to work with PHP-FPM:

sudo nano /etc/lighttpd/lighttpd.conf
Add the following line in the lighttpd.conf file:

include "conf-available/15-fastcgi-php.conf"
Restart lighttpd:

sudo systemctl restart lighttpd
Access the WordPress installation page in a web browser using the IP address or hostname of the server. The setup process should guide you through the rest of the installation process.
These are the basic steps to set up a functional WordPress website with lighttpd, MariaDB, and PHP on a Debian-based system.

****************** MARIADB ********************
mysql -u root -p
// WHEN in mysql shell: 
SHOW DATABASES
SELECT User, Host FROM mysql.user;

********* FAIL2BAN *************
sudo systemctl restart fail2ban
sudo fail2ban-client status ssh
sudo iptables -L -n
sudo tail -f /var/log/fail2ban.log


FAIL2BAN IS: a log-parsing application that scans log files for specific patterns of failed login attempts and temporarily bans the IP addresses responsible for these attempts. The ban can be either in the form of a firewall rule or by rejecting connections from the IP address. This helps to prevent brute-force attacks and protect the system from unauthorized access.


