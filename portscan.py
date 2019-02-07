#!/usr/bin/env python
"""Quickly scans a range of TCP/IP ports for a given address

This script is intended to ONLY interact with targets for which You are
expressly authorized to scan
"""

import socket, threading, itertools, json, re, os, datetime as dt
from optparse import OptionParser

__author__ = "Sean Walsh"
__copyright__ = "Copyright (c) 2018 SeanWalsh95"
__credits__ = ["Sean Walsh", "user:6552846@stackoverflow"]

__license__ = "MIT"
__version__ = "0.1.0"
__maintainer__ = "Sean Walsh"


def TCP_connect(ip, port_range, delay, output):
    for port_number in port_range:
        TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCPsock.settimeout(delay)
        try:
            TCPsock.connect((ip, port_number))
            output[port_number] = 'Listening'
        except:
            output[port_number] = 'Scanned'

# Splits range into n seperate ranges
def split_range(list, n):
    return [list[i::n] for i in range(n)]
def scan_ports(host_ip, delay, port_range, thread_count):
    
    port_ranges_list = split_range( port_range, thread_count )
    
    threads = []        # To run TCP_connect concurrently
    output = {}         # For printing purposes
    
    # Spawning threads to scan ports
    for i in range(thread_count):
        t = threading.Thread(target=TCP_connect, args=(host_ip, port_ranges_list[i], delay, output))
        threads.append(t)

    # Starting threads
    for i in range(thread_count):
        threads[i].start()

    # Locking the script until all threads complete
    for i in range(thread_count):
        threads[i].join()
    
    scan = {'Listening': [], 'Timeout': []}
    for k,v in output.items():
        if v == 'Listening':
            scan['Listening'].append(k)
        else:
            scan['Timeout'].append(k)
    return scan

def out(f,string):
    print(string)
    f.write(string+"\n")
def scan_ip(info_header, host_ip, delay, port_range, thread_count):
    
    log_file = ".\logs\{}\{}[{}-{}]@{}.txt".format(host_ip, host_ip, port_range[0], port_range[-1], dt.datetime.utcnow().timestamp())
    
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file,"w+") as f:
        out(f,info_header)
        
        scan_result = scan_ports(host_ip, delay, port_range, thread_count)
        
        dashes = "-"*59
        out(f,dashes + "\n {:^8} | {:^45} |\n".format("Port", "Description") + dashes)
        for listener in scan_result['Listening']:
            out(f, port_info(listener) )
        out(f,dashes)
        
        if verbose:
            out(f,"\n Timeout Ports:")
            out(f,dashes + "\n {:^8} | {:^45} |\n".format("Port", "Description") + dashes)
            for listener in scan_result['Timeout']:
                out(f, port_info(listener) )
            out(f,dashes)

def port_info( port ):
    global port_list
    
    port_entry = port_list[str(port)]
    meta = ""
    
    if isinstance( port_entry, list ):
        port_desc = port_entry[0]["description"]
        meta = "1-of-{}".format(len(port_entry))
    else:
        port_desc = port_entry["description"]
    
    if len(port_desc) > 35:
        port_desc = port_desc[0:35] + "..."
    
    return " {:8} | {:38} {:6} |".format(str(port), port_desc, meta)
def ip_range_gen(input_string):
    octets = input_string.split('.')
    chunks = [list(map(int, octet.split('-'))) for octet in octets]
    ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]
    
    for address in itertools.product(*ranges):
        yield '.'.join(map(str, address))

def main():
    global verbose, port_ranges
    
    ## DEFAULTS ##
    delay = 0.5
    verbose = False
    ip_range = ["127.0.0.1"]
    thread_count = 100
    range_selection = "common"
    
    
    port_ranges["reserved"] = range(1023)
    port_ranges["full"] = range(65535)
    
    
    usage = "usage: python %prog [options] ip address to scan"
    parser = OptionParser(usage=usage)
    
    parser.add_option("-v", "--verbose",action="store_true", dest="verbose",
                        help="prints extra information about scan")
    parser.add_option("-t", action="store", type=float, dest="timeout",
                        help="Seconds the socket is going to wait until timeout : 0.5s")
    parser.add_option("--threads", action="store", type=int, dest="threads", default=100,
                        help="number of threads to spawn : [100]")
    
    parser.add_option("--common",   action="store_const", const="common",   dest="range", default="common",
                        help="Range of commonly used ports : [default]")
    parser.add_option("--reserved", action="store_const", const="reserved", dest="range",
                        help="Full port range (0-1023) scan")
    parser.add_option("--full",     action="store_const", const="full",     dest="range",
                        help="Full port range (0-65535) scan")
    parser.add_option("-r",         action="store",       type=str,         dest="cust_range",
                        help="Specify name of custom range i.e. 'common_fast', 'simple'")
    
    (options, args) = parser.parse_args()
    
    
    if options.verbose != None:
        verbose = options.verbose
    if options.timeout != None:
        delay = options.timeout
    if options.threads != None:
        thread_count = options.threads
    if options.cust_range != None:
        range_selection = options.cust_range
    elif options.range != None:
        range_selection = options.range
    if args[0] !=  None:
        ip_arg = args[0]
    
    port_range = port_ranges[range_selection]
    
    if re.search(r'\d{1,3}\.[\d-]*\.[\d-]*\.[\d-]*', ip_arg):
        ip_range = list(ip_range_gen(ip_arg))
        if len(ip_range) > 1:
            print( "\n"+"@"*45 )
            print( "SCANNING {} IP ADDRESSES".format(len(ip_range)).center(45) )
            total_ert_s = (len(ip_range) * ( (len(port_range)*delay) / thread_count ))
            print( "TOTAL ESTIMATED RUNTIME: {}".format(str(dt.timedelta(seconds=total_ert_s))).center(45) )
            print( "@"*45+"\n" )
    else:
        ip_range = [ip_arg]
    
    for ip in ip_range:
        # ERT in seconds based on (scans_to_perform * socket_delay) / thread_count
        ert_sec = ( len(port_range) * delay ) / thread_count
        ert = dt.timedelta( seconds=ert_sec )
        
        padding = 15 + max( len(ip), len(range_selection), len(str(delay))+1, len(str(ert)) )
        
        info =  "\n"+"-"*padding+"\n"
        info += "{:>12}: {}\n".format("Scanning IP", ip )
        info += "{:>12}: {}\n".format("Range", range_selection )
        info += "{:>12}: {}\n".format("Timeout", str(delay)+"s" )
        info += "{:>12}: {}".format("ERT", str(ert) )
        
        scan_ip(info, ip, delay, port_range, thread_count)

if __name__ == "__main__":
    global port_list, port_ranges
    global port_ranges
    with open('ports.json') as p:
        json_dict = json.load(p)
        port_list = json_dict["ports"]
        port_ranges = json_dict["ranges"]
    main()