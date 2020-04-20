import socket
import subprocess
import sys
import os
from datetime import datetime
import struct
import textwrap
import scapy.all as scapy
import argparse
import prettytable
from prettytable import PrettyTable
from scapy.layers import http
import threading
from threading import Thread
import time
from bs4 import BeautifulSoup
import requests
import requests.exceptions
import urllib3
from urllib.parse import urlsplit
from collections import deque
import re
import argparse
#from pexpect import pxssh
import nmap




os.system("clear")
print("Tool started")
print('\n')

print(" 1. Port Scanning ")
print(" 2. Network Sniffer ")
print(" 3. Password cracking ")
print(" 4. Email/Phone/Banner")
print(" 5. Vunerability Scanner")
print(" 6. Running Service ")


op = input("Choose your desired Option : ")

#First case
elif op == "1" :
if __name__ == '__main__':
	target = raw_input('IP: ')
	targetIP = gethostbyname(target)

	#scan reserved ports
	for i in range(20, 1025):
		s = socket(AF_INET, SOCK_STREAM)

		result = s.connect_ex((targetIP, i))

		if(result == 0) :
			print 'Port %d:' % (i,)
		s.close()
#reference:https://gist.github.com/hmert/934734
    
#second case
# reference https://github.com/buckyroberts/Python-Packet-Sniffer/blob/master/sniffer.py
elif op == "2" :
def main():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))

    pcap.close()



#Third case

    #Partial Reference "https://github.com/j2sg/johnny"
    
elif op == "3" :
    Found = False
    Fails = 0

    maxConnections = 5
    connection_lock = threading.BoundedSemaphore(maxConnections)

    def nmapScan(tgtHost):
            nmapScan = nmap.PortScanner()
            nmapScan.scan(tgtHost, '22')
            state = nmapScan[tgtHost]['tcp'][22]['state']
            return state

    def connect(host, user, password, release):
            global Found
            global Fails
            try:
                    s = pxssh.pxssh()
                    s.login(host, user, password)
                    print('\n[+] Password Found: {}\n'.format(password.decode('utf-8')))
                    Found = True
                    s.logout()
            except Exception as e:
                    if 'read_nonblocking' in str(e):
                            Fails += 1
                            time.sleep(5)
                            connect(host, user, password, False)
                    elif 'synchronize with original prompt' in str(e):
                            time.sleep(1)
                            connect(host, user, password, False)
            finally:
                    if release: 
                            connection_lock.release()

    def main():

            host =input("Please enter host: ")
            user= input("Please enter User: ")
            passwordFile=input("Please enter thw password file location: ")
            global Found
            global Fails
            print('Welcome to SSH Dictionary Based Attack')
            print('[+] Checking SSH port state on {}'.format(host))
            if nmapScan(host) == 'open':
                    print('[+] SSH port 22 open on {}'.format(host))
            else:
                    print('[!] SSH port 22 closed on {}'.format(host))	
                    print('[+] Exiting Application.\n')
                    exit()

            print('[+] Loading Password File\n')
            
            try:
                    fn = open(passwordFile, 'rb')
            except Exception as e:
                    print(e)
                    exit(1)
            
            for line in fn:
                    if Found:
                            # print('[*] Exiting Password Found')
                            exit(0)
                    elif Fails > 5:
                            print('[!] Exiting: Too Many Socket Timeouts')
                            exit(0)

                    connection_lock.acquire()
                    
                    password = line.strip()
                    print('[-] Testing Password With: {}'.format(password.decode('utf-8')))
                    
                    t = Thread(target=connect, args=(host, user, password, True))
                    t.start()
            
            while (threading.active_count() > 1):
                    if threading.active_count() == 1 and Found != True:
                            print('\nPassword Not Found In Password File.\n')
                            print('[*] Exiting Application')
                            exit(0)
                    elif threading.active_count() == 1 and Found == True:
                            print('[*] Exiting Application.\n')

    if __name__ == '__main__':
            main()

#Fourth case

        #reference from https://www.pyimagesearch.com/2015/10/12/scraping-images-with-python-and-scrapy/
elif op == "4" :
    new_urls = deque(['https://www.google.ca'])
    processed_urls = set()
    emails = set()
    while len(new_urls):
        url=new_urls
        processed_urls.add(url)
        z=PrettyTable()
        z.field_names = ["URLs", "email"]
        parts = urlsplit(url)
        base_url = "{0.scheme}://{0.netloc}".format(parts)
        path = url[:url.rfind('/')+1] if '/' in parts.path else url

        print("Processing %s" % url)
        try:
            response = requests.get(url)
        except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
            continue

        new_emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text, re.I))
        emails.update(new_emails)

        soup = BeautifulSoup(response.text, 'html.parser')
        
        for anchor in soup.find_all("a"):
            link = anchor.attrs["href"] if "href" in anchor.attrs else ''
            if link.startswith('/'):
                link = base_url + link
            elif not link.startswith('http'):
                link = path + link
            if not link in new_urls and not link in processed_urls:
                z.add_row(link)
        z.print()

#Fifth case

       #reference https://gist.github.com/kf4bzt/ff0b499821c12722341dbdbde3f57e60
elif op == "5" :

        x=PrettyTable(['Possible Vulnerabilites'])
        target_ip =input("Please enter target ip: ")
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        client_list = []

        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict) 
        x.add_row(client_list)
        print(x)
 

#Sixth case
elif op == "6" :
   #reference 'https://github.com/Tib3rius/AutoRecon/blob/master/autorecon.py'
    def main():
       if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.')
    parser.add_argument('targets', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs="*")
    parser.add_argument('-t', '--targets', action='store', type=str, default='', dest='target_file', help='Read targets from file.')
    parser.add_argument('-ct', '--concurrent-targets', action='store', metavar='<number>', type=int, default=5, help='The maximum number of target hosts to scan concurrently. Default: %(default)s')
    parser.add_argument('-cs', '--concurrent-scans', action='store', metavar='<number>', type=int, default=10, help='The maximum number of scans to perform per target host. Default: %(default)s')
    parser.add_argument('--profile', action='store', default='default', dest='profile_name', help='The port scanning profile to use (defined in port-scan-profiles.toml). Default: %(default)s')
    parser.add_argument('-o', '--output', action='store', default='results', dest='output_dir', help='The output directory for results. Default: %(default)s')
    parser.add_argument('--single-target', action='store_true', default=False, help='Only scan a single target. A directory named after the target will not be created. Instead, the directory structure will be created within the output directory. Default: false')
    parser.add_argument('--only-scans-dir', action='store_true', default=False, help='Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: false')
    parser.add_argument('--heartbeat', action='store', type=int, default=60, help='Specifies the heartbeat interval (in seconds) for task status messages. Default: %(default)s')
    nmap_group = parser.add_mutually_exclusive_group()
    nmap_group.add_argument('--nmap', action='store', default='-vv --reason -Pn', help='Override the {nmap_extra} variable in scans. Default: %(default)s')
    nmap_group.add_argument('--nmap-append', action='store', default='', help='Append to the default {nmap_extra} variable in scans.')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. Repeat for more verbosity.')
    parser.add_argument('--disable-sanity-checks', action='store_true', default=False, help='Disable sanity checks that would otherwise prevent the scans from running. Default: false')
    parser.error = lambda s: fail(s[0].upper() + s[1:])
    args = parser.parse_args()

    single_target = args.single_target
    only_scans_dir = args.only_scans_dir

    errors = False

    if args.concurrent_targets <= 0:
        error('Argument -ch/--concurrent-targets: must be at least 1.')
        errors = True

    concurrent_scans = args.concurrent_scans

    if concurrent_scans <= 0:
        error('Argument -ct/--concurrent-scans: must be at least 1.')
        errors = True

    port_scan_profile = args.profile_name

    found_scan_profile = False
    for profile in port_scan_profiles_config:
        if profile == port_scan_profile:
            found_scan_profile = True
            for scan in port_scan_profiles_config[profile]:
                if 'service-detection' not in port_scan_profiles_config[profile][scan]:
                    error('The {profile}.{scan} scan does not have a defined service-detection section. Every scan must at least have a service-detection section defined with a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the result.')
                    errors = True
                else:
                    if 'command' not in port_scan_profiles_config[profile][scan]['service-detection']:
                        error('The {profile}.{scan}.service-detection section does not have a command defined. Every service-detection section must have a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the results.')
                        errors = True
                    else:
                        if '{ports}' in port_scan_profiles_config[profile][scan]['service-detection']['command'] and 'port-scan' not in port_scan_profiles_config[profile][scan]:
                            error('The {profile}.{scan}.service-detection command appears to reference a port list but there is no port-scan section defined in {profile}.{scan}. Define a port-scan section with a command and corresponding pattern that extracts port numbers from the result, or replace the reference with a static list of ports.')
                            errors = True

                    if 'pattern' not in port_scan_profiles_config[profile][scan]['service-detection']:
                        error('The {profile}.{scan}.service-detection section does not have a pattern defined. Every service-detection section must have a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the results.')
                        errors = True
                    else:
                        if not all(x in port_scan_profiles_config[profile][scan]['service-detection']['pattern'] for x in ['(?P<port>', '(?P<protocol>', '(?P<service>']):
                            error('The {profile}.{scan}.service-detection pattern does not contain one or more of the following matching groups: port, protocol, service. Ensure that all three of these matching groups are defined and capture the relevant data, e.g. (?P<port>\d+)')
                            errors = True

                if 'port-scan' in port_scan_profiles_config[profile][scan]:
                    if 'command' not in port_scan_profiles_config[profile][scan]['port-scan']:
                        error('The {profile}.{scan}.port-scan section does not have a command defined. Every port-scan section must have a command and a corresponding pattern that extracts the port from the results.')
                        errors = True

                    if 'pattern' not in port_scan_profiles_config[profile][scan]['port-scan']:
                        error('The {profile}.{scan}.port-scan section does not have a pattern defined. Every port-scan section must have a command and a corresponding pattern that extracts the port from the results.')
                        errors = True
                    else:
                        if '(?P<port>' not in port_scan_profiles_config[profile][scan]['port-scan']['pattern']:
                            error('The {profile}.{scan}.port-scan pattern does not contain a port matching group. Ensure that the port matching group is defined and captures the relevant data, e.g. (?P<port>\d+)')
                            errors = True
            break

    if not found_scan_profile:
        error('Argument --profile: must reference a port scan profile defined in {port_scan_profiles_config_file}. No such profile found: {port_scan_profile}')
        errors = True

    heartbeat_interval = args.heartbeat

    nmap = args.nmap
    if args.nmap_append:
        nmap += " " + args.nmap_append

    outdir = args.output_dir
    srvname = ''
    verbose = args.verbose

    raw_targets = args.targets
    targets = []

    if len(args.target_file) > 0:
        if not os.path.isfile(args.target_file):
            error('The target file {args.target_file} was not found.')
            sys.exit(1)
        try:
            with open(args.target_file, 'r') as f:
                lines = f.read()
                for line in lines.splitlines():
                    line = line.strip()
                    if line.startswith('#') or len(line) == 0: continue
                    if line not in raw_targets:
                        raw_targets.append(line)
        except OSError:
            error('The target file {args.target_file} could not be read.')
            sys.exit(1)

    for target in raw_targets:
        try:
            ip = str(ipaddress.ip_address(target))

            if ip not in targets:
                targets.append(ip)
        except ValueError:

            try:
                target_range = ipaddress.ip_network(target, strict=False)
                if not args.disable_sanity_checks and target_range.num_addresses > 256:
                    error(target + ' contains ' + str(target_range.num_addresses) + ' addresses. Check that your CIDR notation is correct. If it is, re-run with the --disable-sanity-checks option to suppress this check.')
                    errors = True
                else:
                    for ip in target_range.hosts():
                        ip = str(ip)
                        if ip not in targets:
                            targets.append(ip)
            except ValueError:

                try:
                    ip = socket.gethostbyname(target)

                    if target not in targets:
                        targets.append(target)
                except socket.gaierror:
                    error(target + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
                    errors = True

    if len(targets) == 0:
        error('You must specify at least one target to scan!')
        errors = True

    if single_target and len(targets) != 1:
        error('You cannot provide more than one target when scanning in single-target mode.')
        sys.exit(1)

    if not args.disable_sanity_checks and len(targets) > 256:
        error('A total of ' + str(len(targets)) + ' targets would be scanned. If this is correct, re-run with the --disable-sanity-checks option to suppress this check.')
        errors = True

    if errors:
        sys.exit(1)

    with ProcessPoolExecutor(max_workers=args.concurrent_targets) as executor:
        start_time = time.time()
        futures = []

        for address in targets:
            target = Target(address)
            futures.append(executor.submit(scan_host, target, concurrent_scans))

        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)
            sys.exit(1)

        elapsed_time = calculate_elapsed_time(start_time)
        info('{bgreen}Finished scanning all targets in {elapsed_time}!{rst}')

else :
   print(" Enter a valid option... ")
