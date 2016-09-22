#!/usr/bin/python
# Basic python check to see if a port is open, can be used for many different applications.
# Author: Mark Austin <ganthore@gmail.com>

# Usage:
# ./check_port.py <host/ip> <port>

import socket;
import sys;
import errno;

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def check_host(remote_ip,remote_port):
	remote_ip = sys.argv[1]
	remote_port = int(sys.argv[2])
	result = sock.connect_ex((remote_ip,remote_port))
	if result == 0:
   		print "[SUCCESS] Host %s has port %s open" % (remote_ip, remote_port)
		sys.exit(0)
	else:
   		print "[ERROR] Host %s does not have port %s open" % (remote_ip, remote_port)
		sys.exit(1)

check_host(sys.argv[1], sys.argv[2])
