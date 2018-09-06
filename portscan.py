#!/usr/bin/env python
"""Quickly scans a range of TCP/IP ports for a given address

This script is intended to ONLY interact with targets for which You are
expressly authorized to scan
"""

import socket, threading, datetime
from optparse import OptionParser

__author__ = "Sean Walsh"
__copyright__ = "Copyright (c) 2018 SeanWalsh95"
__credits__ = ["Sean Walsh", "user:6552846@stackoverflow"]

__license__ = "MIT"
__version__ = "0.0.1"
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
        if verbose:
            print("{} Scanned".format( str(port_number) ))


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

    # Printing listening ports from small to large
    for i in port_range:
        if output[i] == 'Listening':
            print(str(i) + ': ' + output[i])


def split_range(list, n):
    return [list[i::n] for i in range(n)]

def main():
    global verbose
    
    ## DEFAULTS ##
    delay = 0.5
    verbose = False
    host_ip = "127.0.0.1"
    thread_count = 100
    range_selection = "common"
    
    port_ranges = {
        "common"    : [ 20,21,22,23,25,37,53,80,443,88,109,110,115,2049,3389,8008,8080,9050,9051,32400 ],
        "reserved"  : range(1023),
        "full"      : range(65535)
    }
    
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
    
    (options, args) = parser.parse_args()
    
    
    if options.verbose != None:
        verbose = options.verbose
    if options.timeout != None:
        delay = options.timeout
    if options.threads != None:
        thread_count = options.threads
    if options.range != None:
        range_selection = options.range
    if args[0] !=  None:
        host_ip = args[0]
    
    port_range = port_ranges[range_selection]
    
    # ETA in seconds based on (scans_to_perform * socket_delay) / thread_count
    eta_sec = ( len(port_range) * delay ) / thread_count
    eta = datetime.timedelta( seconds=eta_sec )
    
    print("-----------------------------")
    print("Scanning IP: {}".format( host_ip ))
    print("      Range: {}".format( range_selection ))
    print("    Timeout: {}s".format( delay ))
    print("        ETA: {}".format( str(eta) ))
    print("-----------------------------")
    
    scan_ports(host_ip, delay, port_range, thread_count)

if __name__ == "__main__":
    main()
