import os, sys, MySQLdb, pdb, subprocess, re, random, string, argparse, smtplib, time, socket
from timeout import timeout
from MySQLdb import Error

#sys.argv[1] == databaseName
#sys.argv[2] == table
def create_dbConnection():
    try:
        # trying to create a connection with the proceeding connection
        a = MySQLdb.connect(user='REDACTED', passwd='REDACTED', db='bounties', unix_socket="/opt/lampp/var/mysql/mysql.sock")
        return a
    except Error as e:
        print(e)
    return None

def findInOut(a, b):
    for item in a.split(' ; ')[2].split(' , '):
        if item.startswith(b):
            return item.split('^')[1]

def removeByKey(providedKey):
    data = []
    cfile = open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'r')
    for a in cfile.readlines():
        if providedKey in a.split(' : ')[-1]:
            next
        else:
            data.append(a)
    with open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'w') as file:
        file.writelines(data)


def textNotification(conn, gmail, password, toAddress):
        data = []
        s = smtplib.SMTP('smtp.gmail.com',587)
        s.starttls()
        s.login(gmail,password)
        cfile = open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'r')
        for a in cfile.readlines():
            if 'True' in a.split(' ; ')[3]:
                data.append(a)
                next
            else:
                domain = findInOut(a, 'Domain^')+'\n'
                program = a.split(' ; ')[1][:-11]+'\n'
                researchOnly = findInOut(a, 'Research Only^')+'\n'
                key = a.split(' ; ')[-1].rstrip()
                message = '\n|Domain| '+domain+'|Program| '+program+'|ResearchOnly| '+researchOnly+'|Key| '+key
                msg = """From: %s
                To: %s
                Subject: 
                %s"""%(gmail, toAddress,message)
                s.sendmail(gmail,toAddress,msg)
                cdata = a.split(' ; '); cdata[3] = 'True'; cdata = ' ; '.join(cdata)
                data.append(cdata)
        s.quit()
            # do some replacing thing the file
        with open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'w') as file:
            file.writelines(data)

def sendToDatabase(conn):
        cur = conn.cursor()
        cfile = open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'r')
        for a in cfile.readlines():
            a = a.rstrip()
            table = a.split(' ; ')[1]
            column = []
            values = []
            for b in a.split(' ; ')[2].split(' , '):
                column.append('`'+b.split('^')[0]+'`'   )
                values.append('\''+b.split('^')[1]+'\'')
            fcolumn = ', '.join(column)
            fvalues = ', '.join(values)
            statem = 'INSERT INTO '+table+'('+fcolumn+') VALUES ('+fvalues+')'
            try:
                cur.execute(statem)
            except Exception as e:
                pass
        conn.commit()
        cfile = open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'w')
        cfile.write('')
        cfile.close

def removeBasedOnPattern(pattern, program):
    cfile = open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'r')
    keep = []
    for a in cfile.readlines():
        if program in a.split(' ; ')[1]:
            if 'Domain^'+pattern in a:
                next
            else: 
                keep.append(a)
    with open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'w') as file:
        file.writelines(keep)

@timeout(800)
def nmapOnDomain(domain, ports):
    #nmap -sS -A example.com --> faster tcp with OS Grepping
    #nmap -sU example.com --> UDP ports
    FNULL = open(os.devnull, 'w')
    portDict = {"full" : "-p-", "fast" : "-F", "normal": ""}
    #portDict['full']
    inputFile = '~/arsenal/tempFiles/nmap.out'
    print 'Starting Nmap on: \t',domain
    startOutput = subprocess.call('nmap -sS -A -oG %s %s %s'%(inputFile, portDict[ports], domain), shell=True, stdout=FNULL)
    nmapOut = subprocess.check_output('~/gitRepos/pushToDatabase/messingWithDatabase/scanreport.sh -f %s'%(inputFile), shell=True)
    ports = []
    for index, a in enumerate(nmapOut.split('\n')):
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
    return ' , '.join(ports)
    # Returns open ports

def select_webAppFromPrograms(conn, scope, cProgram):
    cur = conn.cursor()
    if scope:
        statem = "SELECT `In Scope Domains` FROM programs WHERE Name=\'%s\'" % cProgram
        cur.execute(statem)
        a = cur.fetchone()[0].split(' , ')
        return a 
    else:
        statem = "SELECT `Out of Scope Domains` FROM programs WHERE Name=\'%s\'" % cProgram
        cur.execute(statem)
        a = cur.fetchone()[0].split(' , ')
        return a
def returningStatuscode(prompt, domainListLength):
    a = []
    if prompt == 'next' or prompt.rstrip() == 'n':
        a.append(0)
        a.append(0)
    elif prompt.startswith('nc '):
        try:
            ### The line below is so the status code gets appended only after the port is verified as a number
            port = int(prompt[3:])
            a.append(1)
            a.append(int(prompt[3:]))
        except Exception,e:
            a.append(-1)
            a.append(prompt)
            print e
            pass
    elif prompt == 'info':
        a.append(2)
        a.append(2)
    elif prompt == 'checkInt':
        a.append(3)
        a.append(3)
    elif prompt.startswith('go '):
        try: 
            ### Same concept as for startsWith('nc ')
            value = int(prompt[3:])
            if value > domainListLength-1:
                raise ValueError('[-] The Value(%s) was bigger than the domain list(%s)'%(value, domainListLength-1))
            a.append(4)
            a.append(int(prompt[3:]))
        except Exception,e: 
            a.append(-1)
            a.append(prompt)
            print e 
            pass
    else: 
        a.append(-1)
        a.append(prompt)
    return a

def main(): 
    parser = argparse.ArgumentParser(description='databaseActions')
    parser.add_argument('-ce', help='"Program Domain fileOfEndpoints" This will try to update the provided domain with any new endpoints found use `output >> ~/firstEndpointLocation` to update the list accordingly')
    parser.add_argument('-b', help='"Program" Search Using Brutesubs')
    parser.add_argument('-g', help='"Program File" Search Using Gobuster... Provide the program name, spaces and a file or directory ending in /')
    parser.add_argument('-dl', help='"Program File" File of domains to database')
    parser.add_argument('-c', help='"Program" Attempt to find new domains based on the other domains Certs')
    parser.add_argument('-r', action='store_true', help='Read Changes.txt')
    parser.add_argument('-rd', help='"Domain" Remove based on domain')
    parser.add_argument('-rk', help='"5CharacterKey" Remove based on key')
    parser.add_argument('-rcp', help='"WordOrPattern:Program" Remove based on a character/s in domain by program')
    parser.add_argument('-t', help='"gmail:password:toAddress" Check for text Notifications') 
    parser.add_argument('-skd', help='show key by domain') 
    parser.add_argument('-n', help='program:{subdomain range specific?}domainOrBlank:{Port Range}Full/Normal/Fast:{Current Database Status}AllOrEmpty <-- The last value is speaking of the ports status in the database. Run nmap on domains e.g. CompanyOrProgram:test.com:Full:All , CompanyOrProgram::Normal:Empty')
    parser.add_argument('--startBrowsers', help='"Program", start enumerating through domains from a programs database')
    parser.add_argument('-p', action='store_true', help='purge changes.txt')
    parser.add_argument('-s', action='store_true', help='Send to database')
    parser.add_argument('-e', help='"Program" Run EyeWitness')
    parser.add_argument('-printMe', help='"Program" Print all domains in database for program')
    args = parser.parse_args()
    conn = create_dbConnection()
	#Read changes file
    if args.startBrowsers: 
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(args.startBrowsers))
        domainsSQL = cur.fetchall()
        domainList = []
        for a in domainsSQL:
            # a = re.findall(r"['](.*?)[']", str(x))
            domainList.append(str(a).split("'")[1])
        domainListLength = len(domainList)
        count = 0
        # for index2, a in enumerate(domainList):
        while count < domainListLength:
            a = domainList[count]
            if a == '':
                count += 1
                continue
            else:
                cur.execute('SELECT * FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\''%(args.startBrowsers, a))
                data = list(cur.fetchone())
                for index, b in enumerate(data):
                    if b == None:
                        data[index] = 'Not Done'
                researchBoolean = data[1]
                dnsLine = data[2]
                endpointsFile = data[3]
                nsLine = data[4]
                ports = '\n\t'.join(data[5].split(' , '))
                builtWith = data[6]
                contentSecurityLine = data[7]
                xframesLine = data[8]
                xssProtectionLine = data[9]
                contentTypeLine = data[10]
                infoPrint = True
                openWindow = True
                while True:
                    # pdb.set_trace()
                    if openWindow:
                        openWindow = False
                        subprocess.call("~/arsenal/browsers/firefoxDevAddition/firefox " + 'http://' + a, shell=True)
                        subprocess.call("~/arsenal/browsers/firefoxDevAddition/firefox " + 'https://' + a, shell=True)
                    if infoPrint:
                        infoPrint = False
                        print '%s/%s'%(count,domainListLength-1)
                        print 'Domain: '+a
                        print 'Research Only: '+researchBoolean
                        print 'DNS: '+dnsLine
                        print 'NS: '+nsLine
                        print 'Ports: '+ports
                        print 'Built-With: '+builtWith
                        print 'Content-Security-Policy: '+contentSecurityLine
                        print 'X-Frames-Options: '+xframesLine
                        print 'X-Xss-Protection: '+xssProtectionLine
                        print 'X-Content-Type-Options: '+contentTypeLine+'\n'
                    prompt = returningStatuscode(raw_input('next(n)/info/nc {integer}/go {integer}/checkInt: '), domainListLength)
                    if prompt[0] == 0: 
                        ###Continue 
                        print(chr(27) + "[2J")
                        count += 1
                        break
                    if prompt[0] == 1:
                        ###Starts netcat
                        host = a
                        port = prompt[1]

                        print 'Connecting... ',
                        try:
                            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            c.connect((host, port))
                            try:
                                print 'Success!'
                                while 1: 
                                    d = raw_input("(tcp-shell) $ ")
                                    c.send(d + "\n");
                                    result = c.recv(1024).strip();
                                    if not len(result):
                                        print "[-] Response Empty"
                                        c.close()
                                        break
                                    print result
                            except KeyboardInterrupt:
                                print "\n[-] ^C Received, closing connection"
                                c.close()
                            except EOFError:
                                print "\n[-] ^D Recieved, closing connection"
                                c.close()
                        except KeyboardInterrupt:
                            print '\n[-] ^C Received, closing connection' 
                            c.close()
                        except socket.error: 
                            print 'Fail'

                    if prompt[0] == 2:
                        ###Prints info 
                        print(chr(27) + "[2J")
                        infoPrint = True

                    if prompt[0] == 3:
                        ###Checks internet
                        print '    Checking internet...',
                        try: 
                            host = socket.gethostbyname('www.google.com')
                            c = socket.create_connection((host, 80), 2)
                            print 'Success!'
                        except Exception,e: 
                            print 'Failed'
                            print '    '+str(e)
                    if prompt[0] == 4:
                        ###Go to a specific number 
                        count = prompt[1]
                        break

                    if prompt[0] == -1:
                        print '[-] Provided: '+prompt[1]
                        print '[-] Format wasn\'t understandable --- e.g. nc 8080, info, next'
                        ###Input was not understood

    if args.dl:
        if not len(args.dl.split()) == 2:
            print '[-] -dl "datbaseProgram FileLocation"'
            exit()
        else:
            program = args.dl.split()[0]
            cur = conn.cursor()
            with open(args.dl.split()[1]) as file:
                for line in file:
                    try:
                        cur.execute("INSERT INTO "+program+"_liveWebApp(`Domain`, `Research Only`) VALUES ('"+line[:-1]+"','False')")
                    except Exception,e:
                        pass
            conn.commit()
    if args.printMe: 
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(args.printMe))
        domainsSQL = list(cur.fetchall())
        domainList = []
        for a in domainsSQL:
            # a = re.findall(r"['](.*?)[']", str(x))
            domainList.append(str(a).split("'")[1])
        for a in domainList:
            if a.endswith('.'):
                print a
                try:
                    cur.execute('DELETE FROM `'+args.printMe+'_liveWebApp` WHERE `Domain` = \''+a+'\'')
                except Exception,e:
                    print e
                    pass
                conn.commit()
    if args.e:
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(args.e))
        domainsSQL = list(cur.fetchall())
        domainList = []
        for a in domainsSQL:
            # a = re.findall(r"['](.*?)[']", str(x))
            domainList.append(str(a).split("'")[1])
        for a in domainList:
            print a 
    if args.c:
        FNULL = open(os.devnull, 'w')
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(args.c)) 
        domainsSQL = list(cur.fetchall())
        domainList = []
        inScope = []
        for a in select_webAppFromPrograms(conn, True, args.c):
            if a[:2] == '*.':
                inScope.append(a[2:])
        for a in domainsSQL:
            # a = re.findall(r"['](.*?)[']", str(x))
            domainList.append(str(a).split("'")[1])
        for a in domainList:
            subprocess.call('/root/arsenal/recon/DNS\ Discovery/crtsh/crt.sh %s'%(a), shell=True, stdout=FNULL)
            data = subprocess.check_output('cat ~/arsenal/tempFiles/crt.temp', shell=True)
            for b in filter(None, data.split('\n')):
                if b[:2] == '*.':
                    next
                else:
                    info = b.split('.')
                    try: 
                        if info[-2]+'.'+info[-1] in inScope:
                            cur.execute("INSERT INTO "+args.c+"_liveWebApp(`Domain`, `Research Only`) VALUES ('"+b+"','False')")
                            print "Found new inScope domain: "+b
                    except Exception,e: 
                        print e
                        pass




    if args.n:
        portArgs = ['full', 'normal', 'fast']
        valueArgs = ['all', 'empty']
        a = args.n.split(':')
        if not len(a) == 4:
            print "Incorrect Format Check --help"
            exit()
        program = a[0]
        domain = a[1]
        if not any(x in a[2].lower() for x in portArgs):
            print '\nThe Port Argument was not understandable... "Full", "Normal", "Fast"'
            exit()
        ports = a[2].lower()
        if not any(x in a[3].lower() for x in valueArgs):
            print '\nThe Current Value argument was not understandable... "All", "Empty"'
            exit()
        currentValue = a[3].lower() 
        ### Setup Done
        ### Begin 
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(program)) 
        domainsSQL = list(cur.fetchall())
        domainList = []
        if currentValue == 'all':
            for a in domainsSQL:
                # a = re.findall(r"['](.*?)[']", str(x))
                domainList.append(str(a).split("'")[1])
        elif currentValue == 'empty':
            tempList = []
            for a in domainsSQL:
                tempList.append(str(a).split("'")[1])
            for a in tempList:
                cur = conn.cursor()
                cur.execute('SELECT Ports FROM %s_liveWebApp WHERE Domain=\"%s\"'%(program,a))
                if cur.fetchone()[0] == None:
                    domainList.append(a)
        if domain != '':
            domainList2 = [a for a in domainList if domain in a]
            domainList = domainList2
        for a in domainList: 
            try:
                b = nmapOnDomain(a, ports)
                cur.execute("UPDATE %s_liveWebApp SET `Ports` = \""%(program)+b+"\" WHERE `Domain` LIKE \'%s\'"%(a))
                conn.commit()
            except Exception,e:
                print e                
                next
        

        # nmapOnDomains(conn, program, domain, currentValue);
    if args.r:
        with open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'r') as file:
            print file.readlines()
    if args.rk:
        if len(args.rk) != 5:
            print "\n 5 Character key not provided"
            exit()
        else: 
            removeByKey(args.rk)
    if args.ce:
        if len(args.ce.split()) != 3:
            print '\n -ce "program Domain fileOfEndpoints" is the correct format'
            exit()
        else:
            a = args.ce.split()
            program = a[0]
            domain = a[1]
            fileOfEndpoints = a[2]
            try: 
                cur = conn.cursor()
                statem = "SELECT `Endpoints` FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\'"%(program,domain)
                cur.execute("SELECT `Endpoints` FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\'"%(program,domain))
                result = cur.fetchone()[0]
                if result == None:
                    if os.path.isfile(fileOfEndpoints):
                        cur.execute("UPDATE %s_liveWebApp SET `Endpoints` = \'"%(program)+fileOfEndpoints+"\' WHERE `Domain` LIKE \'%s\'"%(domain))
                        conn.commit()
                    else:
                        print 'The file provided did not work properly'
                else:
                    if os.path.isfile(fileOfEndpoints) & os.path.isfile(result):
                        b = open(result, 'r').readlines()
                        c = open(fileOfEndpoints, 'r').readlines()
                        for e in c:
                            if e not in b:
                                print e
                        # d = list(set(b+c))
                        # open(result, 'w').write(''.join(d))
                        # print 'We got here'
                    else:
                        print '\nOne of the paths failed:\n%s\n%s'%(result,fileOfEndpoints)
                        exit()

            except Exception,e:
                print e
                exit()

    if args.p:
        cfile = open('/root/gitRepos/webMap/scripts/databaseData/changes.txt', 'w')
        cfile.write('')
        cfile.close()

    if args.rcp:
        word = args.rcp.split(':')[0]
        program = args.rcp.split(':')[1]
        removeBasedOnPattern(word, program)
    if args.g:
        if len(args.g.split()) != 2:
            print '"File Program" is the format'
            exit()
        elif args.g.split()[1][-1] == '/':
            base = args.g.split()[1]
            program = args.g.split()[0]
            for filename in os.listdir(args.g.split()[1]):
                subprocess.call('python ~/gitRepos/webMap/scripts/messingWithDatabase/programGobusterCheck.py '+program+' '+base+filename,shell=True)
        else: 
            subprocess.call('python ~/gitRepos/webMap/scripts/messingWithDatabase/programGobusterCheck.py '+args.g, shell=True)

    if args.b:
        subprocess.call('python ~/gitRepos/webMap/scripts/messingWithDatabase/programBrutesubs.py '+args.b, shell=True)

    if args.s:
        sendToDatabase(conn)


    if args.t:
        gmail = args.t.split(':')[0]
        password = args.t.split(':')[1]
        toAddress = args.t.split(':')[2]
        textNotification(conn, gmail, password, toAddress)

# random = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(5)])
# 
main()
