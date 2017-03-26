# Is it easier to fix the application than to detect attacks?

Intrusion detection systems are effectively automatic network monitoring systems, which trigger an alert when snorting (pun intended) suspicious traffic in the network. Snort (https://www.snort.org/) is an example of openly available intrusion detection system and it is pretty flexible and widely configurable. In this report a small study is carried out using metasploit framework to attack metasploitable3, while trying to detect attacks with snort.

I acknowledge, that snort is pretty impressive piece of an application, I mean my testing setup contained 34703 individual rules which each are checked for every single request in the network nearly without lag. But the main problem is to me, that snort only detects suspicious traffic. It does not have any clue, if an attack has been successfully executed and system is compromised currently.

It is really common, that internet facing services get loads and loads of malicious traffic just for checking what is actually beneath user interfaces. Do we really want an alert when someone just tries out various wordpress exploits to our machines which have absolutely nothing to do with PHP not to mention wordpress? Naturally, it's possible that we indeed do want an alert - in example, for blacklisting source address. But the bottom line is that the ruleset used must be really carefully crafted and revised reqularly. I also note, that snort is not something that someone just installs and then it just protects network. Using snort properly requires vast knowledge of the protected network and applications running in that network, not to mention keeping up to date with latest vulnerabilities.

Next we examine an array of particular metasploit attacks against metasploitable3 with snort.

## exploit/multi/http/struts2_content_type_ognl

Struts2 multipart file upload vulnerability (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638) which allows attacker to execute remote code without credentials, was disclosed just couple of weeks ago. Even though metasploittable3 does not contain this vulnerability, at least to my knowing, I carried out a little experiment. When exploit was executed from metasploit to snort protected network, snort raised an alert `INDICATOR-SHELLCODE x86 inc ecx NOOP [**] [Classification: Executable code was detected`, but It could not identify the actual exploit. I examined the definition for that rule:

```
alert ip $EXTERNAL_NET any -> $HOME_NET any (msg:"INDICATOR-SHELLCODE x86 inc ecx NOOP"; c
ontent:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; metadata:ruleset community; classtype:shellcode-
detect; sid:1394; rev:17;)
```

Really? If traffic coming from external net contains the string "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" this is raised? This got me thinking, could I raise this alert just by curling something really stupid?

```
curl -H "X-foo: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 55.55.55.5
```

Indeed. Alarm was raised again. When I read more about this, rule makes perfect sense, and it is good and important.

So snort is not peculiarly intelligent in it's own, but with careful enabling of rules it might be really good. I must mention, that I had every single rule enables, because I wanted to get as much false positives as I could in the first place. I googled for an rule to identify that particular struts exploit and it got detected when I added this rule https://gist.github.com/stamparm/a9cf56d40ac3ce5e48e36971946093f8. Alarm `Apache Struts Remote Code Execution (2017-5638` was raised nicely. Now, we must remember, that machine we are protecting is not vulnerable for this anyway!

## auxiliary/dos/http/ms15_034_ulonglongadd

This is really horrible vulnerability. When I did execute it from metasploit, the metasploittable just exploded and rebooted. On the other hand, snort was able to identify this traffic nicely and following alert was raised.

```
03/25-20:51:05.046277  [**] [1:34061:3] SERVER-IIS Microsoft IIS Range header integer overflow attempt [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 55.55.55.1:55224 -> 55.55.55.5:80
```

But what would this help? Attacker can easily DOS service for a period of time and we just see that this is probably why our machines just explode. Patching is the only proper solution for this attack.

## exploit/multi/http/jenkins_script_console

This exploit opens meterpreter session to target machine pretty easily. My setup raises some alerts, but it's not clear what is going on and actual attack is not detected to my understanding.

```
03/25-20:15:53.033276  [**] [1:1390:15] INDICATOR-SHELLCODE x86 inc ebx NOOP [**] [Classification: Executable code was detected] [Priority: 1] {TCP} 55.55.55.1:4444 -> 55.55.55.5:49286
03/25-20:15:54.610575  [**] [1:36611:2] INDICATOR-COMPROMISE Metasploit Meterpreter reverse HTTPS certificate [**] [Classification: Misc activity] [Priority: 3] {TCP} 55.55.55.1:4444 -> 55.55.55.5:49286
```

I think, the latter alert could easily be avoided just by using different certificate from metasploit. And again, that shellcode alert is really broad and usually is disabled.

## auxiliary/scanner/http/http_put

This is more of an security misconfiguration than evil-mind-bogling-ingenious vulnerability. But what was interesting our snort did not have any clue what is going on.

I was able to upload malicious php code really easily to metasploitable3. Here are the metasploit arguments used.

```
FILEDATA  <?php echo "pwned" . (41 + 1);?>
FILENAME  foo.php
RHOSTS    55.55.55.5
RPORT     8585
```

The problem is, that this exploit uses really simple http-requests. I guess one could try to find `<?php` from traffic and raise alert from that? It's easier and more effective to configure security correctly.

## exploit/multi/elasticsearch/script_mvel_rce

This one gets really neatly identified as `SERVER-OTHER ElasticSearch information disclosure attempt` is raised. Again, it does not stop me getting reverse shell to metasploitable3, but then again, that is not even the purpose of snort.

## auxiliary/scanner/http/caidao_bruteforce_login

This doesn't get detected and brute forcing password succeeds. Running this brute forcing raises an alert like this in my environment.

```
03/25-21:05:37.880424  [**] [1:31939:1] SERVER-WEBAPP password sent via POST parameter [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 55.55.55.1:57384 -> 55.55.55.5:80
```

But when we look the rule that was matched

```
alert tcp any any -> any $HTTP_PORTS (msg:"SERVER-WEBAPP password sent via POST parameter"
; flow:to_server,established; content:"password="; fast_pattern:only; http_client_body; me
tadata:service http; classtype:policy-violation; sid:31939; rev:1;)
```

I can trigger such an alarm like this: `curl -X POST -d"password=foo" 55.55.55.5/foo`, and loads and loads of applications still do that. To my understanding, the idea of this rule is to warn that passwords are sent over http instead of https. And then again, if application uses different keyword for passwords it does not get triggered. I.e. curl -X POST -d"pwd=foo" 55.55.55.5/foo` does not trigger an alarm.

So this alarm does not inform us that someone is bruteforcing with caidao, but that we have an application in our network that propably sends passwords openly.

# Summary

Snort is a fascinating software, but it is not a silver bullet. It just merely detects traffic and raises alarms from that, and if I understood correctly, it actually can automatically black list ip:s because of the raised alarms.

To me it seems like snort is not even remotely enough in making environments secure. Even though snort instance is utilised applications still need to be patched regularly and latest disclosed vulnerabilities need to be mitigated.
