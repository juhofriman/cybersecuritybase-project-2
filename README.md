# cybersecuritybase-project-2

This is my take on Cybersecurity base MOOC project 2.

## The setup

Project was carried out with os x computer with metasploittable VM initialized via Vagrant. I modified the Vagrantfile provided slightly by exposing VM directly with known ip to host.

```
  config.vm.network "private_network", ip: "55.55.55.5"
```

This gave me the opportunity to install metasploit to my host machine and tinker with metasploittable "from the outside" - just as in a real life scenario. I knew it had a glassfish application server instance listening port 4848 and yes, I was able to access https://55.55.55.5:4848/ from my host machine.

### Installing snort to metasploittable



### Installing metasploit framework

I installed metasploit framework with these instructions provided here https://null-byte.wonderhowto.com/how-to/mac-for-hackers-install-metasploit-framework-0174517/ and my goal is to learn how to use it from console, instead of provided web-ui. Installing metasploit seemed pretty easy and updating exploit registry can be simply done just by `msfupdate`.

## Initial port scan

First thing I learned is that metasploittable can be set to "easy" and "hard" and this effectively means disabling or enabling firewall. Firewall can be disabled easily by ssh'ing to machine `vagrant ssh` and running `netsh advfirewall set allprofiles state off`. I guess enlightened reader can figure out how to re-enable firewall again.

Next, I figured out how to run nmap from metasploit console.

**nmap with firewall enabled**
```
msf > db_nmap  55.55.55.5
[*] Nmap: Starting Nmap 6.47 ( http://nmap.org ) at 2017-03-16 16:24 EET
[*] Nmap: Nmap scan report for 55.55.55.5
[*] Nmap: Host is up (0.00083s latency).
[*] Nmap: Not shown: 991 filtered ports
[*] Nmap: PORT      STATE SERVICE
[*] Nmap: 21/tcp    open  ftp
[*] Nmap: 22/tcp    open  ssh
[*] Nmap: 80/tcp    open  http
[*] Nmap: 4848/tcp  open  appserv-http
[*] Nmap: 8022/tcp  open  oa-system
[*] Nmap: 8080/tcp  open  http-proxy
[*] Nmap: 9200/tcp  open  wap-wsp
[*] Nmap: 49153/tcp open  unknown
[*] Nmap: 49154/tcp open  unknown
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 5.61 seconds
```

**nmap with firewall disabled**
```
msf > db_nmap  55.55.55.5
[*] Nmap: Starting Nmap 6.47 ( http://nmap.org ) at 2017-03-16 16:23 EET
[*] Nmap: Nmap scan report for 55.55.55.5
[*] Nmap: Host is up (0.0021s latency).
[*] Nmap: Not shown: 977 closed ports
[*] Nmap: PORT      STATE SERVICE
[*] Nmap: 21/tcp    open  ftp
[*] Nmap: 22/tcp    open  ssh
[*] Nmap: 80/tcp    open  http
[*] Nmap: 135/tcp   open  msrpc
[*] Nmap: 139/tcp   open  netbios-ssn
[*] Nmap: 445/tcp   open  microsoft-ds
[*] Nmap: 3306/tcp  open  mysql
[*] Nmap: 3389/tcp  open  ms-wbt-server
[*] Nmap: 4848/tcp  open  appserv-http
[*] Nmap: 7676/tcp  open  imqbrokerd
[*] Nmap: 8009/tcp  open  ajp13
[*] Nmap: 8022/tcp  open  oa-system
[*] Nmap: 8031/tcp  open  unknown
[*] Nmap: 8080/tcp  open  http-proxy
[*] Nmap: 8181/tcp  open  unknown
[*] Nmap: 8443/tcp  open  https-alt
[*] Nmap: 9200/tcp  open  wap-wsp
[*] Nmap: 49152/tcp open  unknown
[*] Nmap: 49153/tcp open  unknown
[*] Nmap: 49154/tcp open  unknown
[*] Nmap: 49157/tcp open  unknown
[*] Nmap: 49158/tcp open  unknown
[*] Nmap: 49159/tcp open  unknown
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 4.69 seconds
```
