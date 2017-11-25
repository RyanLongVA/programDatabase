#!/usr/bin/env python 
import os, sys, MySQLdb, pdb, subprocess, re, random, string 
from timeout import timeout
from MySQLdb import Error

# not sure how nodejs is going to take the path

def create_dbConnection():
    try:
        # trying to create a connection with the proceeding connection
        a = MySQLdb.connect(user='REDACTE', passwd='REDACTED', db='bounties', unix_socket="/opt/lampp/var/mysql/mysql.sock")
        return a
    except Error as e:
        print(e)
    return None

def select_webAppFromPrograms(conn, scope):
    cur = conn.cursor()
    cProgram = sys.argv[1]
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

def checkLiveWebApp(conn, tableName):
    cur = conn.cursor()
    cur.execute("SHOW TABLES;")
    a = re.search(tableName, str(cur.fetchall()))
    if a:
        return True
    else:
        try:
            cur.execute("CREATE TABLE "+tableName+"(Domain VARCHAR(125), `Research Only` TEXT, DNS TEXT, Endpoints TEXT, NS TEXT, Ports TEXT, BuiltWith TEXT, `Content-Security-Policy` TEXT, `X-Frame-Options` TEXT, `X-Xss-Protection` TEXT, `X-Content-Type-Options` TEXT, CONSTRAINT Domains PRIMARY KEY (Domain))")
            cur.execute("SELECT `Tables` FROM programs WHERE `Name`=\'"+sys.argv[1]+"\'")
            startName = cur.fetchone()[0]
            cur.execute("UPDATE `programs` SET `Tables` = \'"+startname+' , '+tableName+"\' WHERE `Name` LIKE \'"+sys.argv[1]+'\'')
            conn.commit()
        except:
            pass
    # Seems tables are automatically saved i.e. don't need to be .commit()'d 

def returnChangesDomains():
    cfile = open('../databaseData/changes.txt', 'r') 
    domains = []
    if len(cfile.read()) == 0:
        return domains  
    for line in cfile.readlines():
        aline = line.split(' ; ')[2].split(' , ')
        for cdata in aline:
            cdata = cdata.split('^')
            if cdata[0] == 'Domain':
                domains.append(cdata[1])
    return domains
                


def checkLiveWebApp_Domains(conn, tableName, domainArray):
    
    changesDomains = returnChangesDomains()
    cfile = open('../databaseData/changes.txt', 'a') 
    if domainArray == None:
        domainArray = []
    for a in domainArray:
        cur = conn.cursor()
        statem = "SELECT * FROM "+tableName+" WHERE Domain=\'"+a+"\'"
        cur.execute(statem)
        if cur.fetchone():
            next
        else:
            if a not in changesDomains:
                print "[+] New Domain Found :",a
                key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(5)])
                cfile.write('bounties ; '+tableName+' ; '+'Domain^'+a+' , Research Only^False ; False ; '+key+'\n')
    cfile.close()

            #cur.execute("INSERT IGNORE INTO "+tableName+"(Domain) VALUES ('%s')"%a)

# def soleDomainAdd(conn, tableName, a):
#     cur = conn.cursor()
#     statem = "SELECT * FROM "+tableName+" WHERE Domain=\'"+a+"\'"
#     cur.execute(statem)
#     if cur.fetchone():
#         return
#     else:
#         print "[+] ",tableName,":",a,"-- Added"
#         cur.execute("INSERT IGNORE INTO "+tableName+"(Domain) VALUES ('%s')"%a)
#     conn.commit()

def cleanTempFolder():
    try:
        subprocess.call('rm -rf ~/arsenal/tempFiles/* &> /dev/null', shell=True)
    except Exception, e:
        print e
        exit()

def callBrutesubs(a):
    try:
        subprocess.call("date >> ~/arsenal/log.txt; cd ~/arsenal/recon/DNS\ Discovery/brutesubs && sh brutesubs.sh "+a+" temp_out; date >> ~/arsenal/log.txt; echo '\n' ~/arsenal/log.txt", shell=True)
        
        # Because of some weird CNAME results
        #if (a == 'algolia.net'):
            #subprocess.call("grep -v '-' ~/arsenal/tempFiles/gobuster.temp > ~/arsenal/tempFiles/gobuster.temp2", shell=True)
            #subprocess.call("cp ~/arsenal/tempFiles/gobuster.temp2 ~/arsenal/tempFiles/gobuster.temp")
        # Code for program specific code e.g. Algolia.net needs to have all '-' s stripped b/c they results in random CNAMES
        b = subprocess.check_output('cat ~/arsenal/tempFiles/brutesubs.temp', shell=True)
        ##See if there's some way to redirect the output to tempFiles
        b = filter(None, b.split('\n'))
        return b
    except Exception, e:
        print e

def main():
    conn = create_dbConnection()

    # connection action block
    inScope = select_webAppFromPrograms(conn, True)
    outScope = select_webAppFromPrograms(conn, False)
    # Does {Program}_liveWebApp exist
    checkLiveWebApp(conn, sys.argv[1]+'_liveWebApp')

    ###Onetime Docker Restart... sometimes fixes internet issues 
    for a in inScope:
        cleanTempFolder()   
        #try:
        if (a[:2] == '*.'):
            a = a[2:]
            b = callBrutesubs(a)
            ## eventually add a dig dig cert call 
            checkLiveWebApp_Domains(conn, sys.argv[1]+'_liveWebApp', b)
        else:
            try:
                cur = conn.cursor()
                statem = "INSERT INTO "+sys.argv[1]+"_liveWebApp(`Domain`, `Research Only`) VALUES ('"+a+"','False')"''
                cur.execute(statem)
                conn.commit()
            except Exception, e:
                pass
        # except Exception, e:
        #     print '[-]',a,'something went wrong:',e
        #     exit()
    for a in outScope:
        cleanTempFolder()
        if (a[:2] == '*.'):
            a = a[2:]
            b = callBrutesubs(a)
            checkLiveWebApp_Domains(conn, sys.argv[1]+'_liveWebApp', b)
if __name__=='__main__':
    main()

