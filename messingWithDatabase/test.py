import os, sys, subprocess
print 'Checking internet'
test = subprocess.call('ping -w4 -c1 google.com', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
print test,
print 'hi'
