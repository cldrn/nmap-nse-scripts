## Brute force SSH with Ncrack and some fine tunning
  
``$ ncrack ssh://192.168.1.1:45120,CL=1,at=6,cd=15s,to=6h -v -f --user root -P ./pass.txt --save ~/ssh_session``

``$ ncrack ftp://192.168.*.*,cr=5 -T5 -v -f --user admin ``

## Brute force SSH with NSE and some fine tunning

`` $ nmap -p22 --script ssh-brute --script-args userdb=<file>,passdb=<file> <target>``


