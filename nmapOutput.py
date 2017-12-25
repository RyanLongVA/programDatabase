#!/bin/python2.7
import subprocess, os, sys
inputFile = '~/arsenal/tempFiles/test'
info = subprocess.check_output('~/gitRepos/webMap/scripts/messingWithDatabase/scanreport.sh -f %s'%(inputFile), shell=True)
ports = []
for index, a in enumerate(info.split('\n')):
	if index != 0:
		tempArray = filter(None, a.split('\t\t'))
		tempArray2 = []
		for b in tempArray:
			if b == '\t':
				next
			else:
				tempArray2.append(b)
		tempArray = tempArray2

		c = ' | '.join(tempArray).replace('\t', ' ')
		if c == '': 
			print c
			next
		else: 
			ports.append(c)
print ' , '.join(ports)
		