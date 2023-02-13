 sudo vim /etc/ssh/sshd_config
 sudo grep Port /etc/ssh/sshd_config
 
 sudo ufw status numbered / allow 80
 
 //change pwd:
 sudo passwd pkatsaro
 
 sudo vim /etc/pam.d/common-password
 sudo vim /etc/login.defs // for expiry time
 sudo chage -l username  //check password expire rules
 
 sudo groupadd evaluating // create an evaluating group
 getent group // check if the group has been created
 
 cut -d: -f1 /etc/passwd // check all local users
sudo adduser new_username // create a username 
sudo usermod -aG evaluating your_username
 getent group user42 // check if the user is the group
 groups // to see which groups the user account belongs to
 chage -l your_new_username // to check if the password rules are working in users
 
 sudo nano /etc/sudoers to go the sudoers file
 
 sudo vim /usr/local/bin/monitoring.sh // after chmod 700 monitoring.sh
 sudo visudo
  your_username ALL=(ALL) NOPASSWD: /usr/local/bin/monitoring.sh under where its written %sudo ALL=(ALL:ALL) ALL
  sudo crontab -u root -e
  @reboot /bin/sh -c "sleep 20 && /full/path/to/your/script.shcao    
  */10 * * * * /usr/local/bin/monitoring.sh this means that every 10 mins, this script will show

