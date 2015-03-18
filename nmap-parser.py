#!/usr/bin/python

import os
import signal
import sys
import xml.etree.ElementTree
import csv
import tabulate

def usage():
#	print len(sys.argv)
#	print sys.argv
	if len(sys.argv) != 3:
		print "\nUsage:"
		print "\tnmap-parser.py -f <file>"
		print "Where \n"
		print "<file> is the XML nmap output to be parsed\n"
		sys.exit(1)

def parse_results(input):
	#ElementTree
	xml_to_parse = xml.etree.ElementTree.parse(input)
	root = xml_to_parse.getroot()
	print ""
	input = input[:-3]
	input += 'csv'
	sys.stdout = open(input, 'w')
	print "IP,Proto,Port,Status,Reason,TTL,Service,Method,Conf,Product,Version,Extra Info"
	for host_value in root.iter("host"):
		ip_value = host_value.find("address")
		IP =ip_value.get("addr")
		ports_value = host_value.find("ports")
		extended = 0
		if ports_value is not None:
			for port_value in ports_value.iter("port"):
				sys.stdout.write (IP + "," + port_value.get("protocol") + "," + port_value.get("portid")+ ",")
				state_value = port_value.find("state")
				sys.stdout.write (state_value.get("state") + "," + state_value.get("reason") + "," + state_value.get("reason_ttl")+ ",")
				if state_value.get("state") == "open":
					extended = "1"
				service_value = port_value.find("service")
				sys.stdout.write (service_value.get("name") + "," + service_value.get("method") + "," + service_value.get("conf"))
				if extended == "1":
					if service_value.get("product") is not None:
						sys.stdout.write ("," + service_value.get("product"))
					if service_value.get("version") is not None:
					 	sys.stdout.write ("," + service_value.get("version"))
					if service_value.get("extrainfo") is not None:
						sys.stdout.write("," + service_value.get("extrainfo"))
				print ""
	sys.stdout = sys.__stdout__
	return input

def print_ouput_file (input):
	input = input[:-3]
	input += 'csv'
	csvfile = csv.reader(open (input,"r"))
	print tabulate.tabulate(csvfile, headers="firstrow")

if __name__ == "__main__":
	usage()
	parameters ={sys.argv[1]:sys.argv[2]}
	try:
		parse_results (parameters["-f"])
	except:
		print "Unknown parameters"
		sys.exit(1)
	print_ouput_file (parameters["-f"])
