1. PORT SCANNING
With this online TCP port scanner you can scan an IP address for open ports. Use this TCP port scan tool to check what services (apache, mail, ssh, ftp, mysql, telnet, dns) are running on your server, test if your firewall is working correctly, view open TCP ports. This port scanner runs a TCP scan on an IP address using Nmap port scanner. 
Do not scan IPs that you do not own, this action may be triggered and blocked by security services.

output

#./scanner.py
Enter host to scan: localhost
Starting scan on host  192.168.1.1
Port 80: OPEN
Port 445: OPEN

Reference 
https://gist.github.com/hmert/934734

2. Network Sniffer

Network sniffing is an integral part of the network analysis capabilities in NPM. The network sniffing modules are designed to provide insight into top metrics, letting you drill down to troubleshoot and allow admins to set dynamic alerting thresholds. 

Reference
https://www.solarwinds.com/network-performance-monitor/use-cases/network-sniffer-tool

3. Password cracking using Johny

John the Ripper (JtR) is one of the hacking tools the Varonis IR Team used in the first Live Cyber Attack demo, and one of the most popular password cracking programs out there.
Requeriments
pip install python-gnupg
pip install python-magic

Partial Reference "https://github.com/j2sg/johnny"

4. Network sniffer

A vulnerability scanner is a computer program designed to assess computers, networks or applications for known weaknesses. In plain words, these scanners are used to discover the weaknesses of a given system.

5. Display running hosts

tool used : AutoRecon
AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services. It is intended as a time-saving tool for use in CTFs and other penetration testing environments (e.g. OSCP). It may also be useful in real-world engagements.

The tool works by firstly performing port scans / service detection scans. From those initial results, the tool will launch further enumeration scans of those services using a number of different tools. For example, if HTTP is found, nikto will be launched (as well as many others).

Everything in the tool is highly configurable. The default configuration performs no automated exploitation to keep the tool in line with OSCP exam rules. If you wish to add automatic exploit tools to the configuration, you do so at your own risk. The author will not be held responsible for negative actions that result from the mis-use of this tool.

Origin
AutoRecon was inspired by three tools which the author used during the OSCP labs: Reconnoitre, ReconScan, and bscan. While all three tools were useful, none of the three alone had the functionality desired. AutoRecon combines the best features of the aforementioned tools while also implementing many new features to help testers with enumeration of multiple targets.

Features
Supports multiple targets in the form of IP addresses, IP ranges (CIDR notation), and resolvable hostnames.
Can scan targets concurrently, utilizing multiple processors if they are available.
Customizable port scanning profiles for flexibility in your initial scans.
Customizable service enumeration commands and suggested manual follow-up commands.
An intuitive directory structure for results gathering.
Full logging of commands that were run, along with errors if they fail.
Global and per-scan pattern matching so you can highlight/extract important information from the noise.
Requirements
Python 3
colorama
toml
