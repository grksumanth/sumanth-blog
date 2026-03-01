`find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null`

`find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

Compile stuff into a shared file so that it can be replaced in place of a shared object that can be executed as a 

`gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`


In the SUID a great example would be changing password by updating password for /etc/shadow file and a user can change his password but not other password this is why passwd command is run as root