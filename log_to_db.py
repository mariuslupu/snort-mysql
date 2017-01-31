###################################################
###################################################
## author:         Marius Lupu                   ##
## IDE used:       Atom                          ##
## OS used:        Ubuntu                        ##
## version:        2017.01.31                    ##
## python version: 2.7.12                        ##
###################################################
###################################################



###################################################
### @import area
### apt-get install python-mysqldb python-mysql.connector
### pip install ipwhois IPy python-geoip-geolite2 pycountry
###################################################
import os
import shutil #copy file
import sys
import re
import datetime
import mysql.connector
import csv
import socket
import ipwhois
import IPy
import geoip
import pycountry


###################################################
### @global variables
###################################################
# debug = True
debug = False
workspace = "<workspace_path>"
current_log_file = "<snort_output_csv_file>"
old_log_file = workspace+"snort.log.old"
veryold_log_file = workspace+"snort.log.veryold"

db_host = "<IP_MySQL_SERVER>"
db_name = "<database_name>"
db_user = "<user>"
db_pass = "<password>"



###################################################
### @class
###################################################
class LogToDB:
    """
    function: default
    things needed: log_new, log_old, log_veryold, debug*
    *debug = optional
    part I.1/5
    """
    def __init__(self, log_new, log_old, log_veryold, db_host, db_name, db_user, db_pass, debug=False):
        """
        log_new = /var/log/snort/alert.csv
        log_old = /var/www/projects/snort/snort.log.old
        log_veryold = /var/www/projects/snort/snort.log.veryold
        db_host
        db_name
        db_user
        db_pass
        """
        ### @class variables
        self.log_new = log_new
        self.log_old = log_old
        self.log_veryold = log_veryold
        self.db_host = db_host
        self.db_name = db_name
        self.db_user = db_user
        self.db_pass = db_pass
        ### @function to run at "startup"
        self.updatingFiles() #part I.2/5
        self.differences() #part I.5/5


    """
    function: creates the necessary files if they do not exists
    things needed: log_new, log_old, log_veryold, debug*
    *debug = optional
    part I.2/5
    """
    def updatingFiles(self):
        if os.path.isfile(self.log_new):
            if os.path.isfile(self.log_veryold):
                if os.path.isfile(self.log_old):
                    os.remove(self.log_veryold)
                    shutil.copyfile(self.log_old, self.log_veryold) # src, dst
                    os.remove(self.log_old)
                    shutil.copyfile(self.log_new, self.log_old) # src, dst
                    if debug:
                        print "-----------------------------------------------"
                        print "updatingFiles():"
                        print "-----------------------------------------------"
                        print " [debug] 0105 Updating files .."
                        print " [debug] All files exists."
                        print " [debug] rm "+self.log_veryold
                        print " [debug] cp "+self.log_old+" "+self.log_veryold
                        print " [debug] rm "+self.log_old
                        print " [debug] cp "+self.log_new+" "+self.log_old
                        print "-----------------------------------------------"
                else:
                    shutil.copyfile(self.log_new, self.log_old) # src, dst
                    if debug:
                        print "-----------------------------------------------"
                        print "updatingFiles():"
                        print "-----------------------------------------------"
                        print " [debug] 0205 Updating files .."
                        print " [debug] File ", self.log_new, "exists!"
                        print " [WARNING] File ", self.log_old, "didn't exists. Don't worry, I just created it."
                        print " [debug] File ", self.log_veryold, "exists!"
                        print " [debug] cp "+self.log_new+" "+self.log_old
                        print " [debug] Please wait 5 min and rerun the code."
                        print "-----------------------------------------------"
                    sys.exit()
            else:
                if os.path.isfile(self.log_old):
                    shutil.copyfile(self.log_old, self.log_veryold) # src, dst
                    os.remove(self.log_old)
                    shutil.copyfile(self.log_new, self.log_old) # src, dst
                    if debug:
                        print "-----------------------------------------------"
                        print "updatingFiles():"
                        print "-----------------------------------------------"
                        print " [debug] 0305 Updating files .."
                        print " [debug] File ", self.log_new, "exists!"
                        print " [debug] File ", self.log_old, "exists!"
                        print " [WARNING] File ", self.log_veryold, "didn't exists. Don't worry, I just created it."
                        print " [debug] cp "+self.log_old+" "+self.log_veryold
                        print " [debug] rm "+self.log_old
                        print " [debug] cp "+self.log_new+" "+self.log_old
                        print "-----------------------------------------------"
                else:
                    shutil.copyfile(self.log_new, self.log_old) # src, dst
                    if debug:
                        print "-----------------------------------------------"
                        print "updatingFiles():"
                        print "-----------------------------------------------"
                        print " [debug] 0405 Updating files .."
                        print " [debug] File ", self.log_new, "exists!"
                        print " [WARNING] File ", self.log_old, "didn't exists. Don't worry, I just created it."
                        print " [ERROR] File ", self.log_veryold, "doesn't exists"
                        print " [debug] cp "+self.log_new+" "+self.log_old
                        print " [debug] Please wait 5 min and rerun the code."
                        print "-----------------------------------------------"
                    sys.exit()
        else:
            if debug:
                print "-----------------------------------------------"
                print "updatingFiles():"
                print "-----------------------------------------------"
                print " [debug] 0505 Updating files .."
                print " [ERROR] File", self.log_new, "doesn't exists!"
                print " [debug] Please check Snort configuration first."
                print "-----------------------------------------------"
            sys.exit()


    """
    function: read CSV String file
    things needed: StringCSV
    part I.3/5
    """
    def readStringCSV(self, StringCSV):
        ### read from CSV file
        ### =================================================================
        ### self.read_current_log_file = open(self.log_new, 'r')
        ### self.reader = csv.reader(self.read_current_log_file, delimiter='\n')
        ### self.list_current_log_file = list(self.reader)
        ### for self.line in self.list_current_log_file:
        ###     self.item = self.line[0].split(",")
        ###     self.timestamp = self.item[0]
        ### =================================================================
        self.StringCSV = StringCSV
        self.item = self.StringCSV.split(",")

        ### default_timestamp:
        ### MONTH/DAY-HOUR:MIN:SEC.MILIIS
        ### 12/02-10:14:44.935310
        self.year = str(datetime.datetime.now().year)
        self.timestamp = self.year+" "+self.item[0].split(".")[0]
        self.timestamp = str(datetime.datetime.strptime(self.timestamp, '%Y %m/%d-%H:%M:%S'))

        self.sig_id = self.item[1]
        self.msg = self.item[2].replace('"','')
        self.proto = self.item[3]
        self.src = self.item[4]
        self.srcport = self.item[5]
        self.dst = self.item[6]
        self.dstport = self.item[7]
        self.ethsrc = self.item[8]
        self.ethdst = self.item[9]

        self.iptype = IPy.IP(self.src).iptype()
        if self.src == socket.gethostbyname('picloud.go.ro'):
            ### 'is' not working
            self.whois = 'PICLOUD.GO.RO'
            self.whois_country = 'Romania'
        elif self.iptype is 'PRIVATE':
            self.whois = 'PRIVATE IP'
            self.whois_country = 'Romania'
        elif self.iptype is 'PUBLIC':
            self.ipwhois = ipwhois.IPWhois(self.src).lookup_whois()
            self.whois = self.ipwhois['nets'][0]['description'].split("\n")[0]
            self.whois_code = geoip.geolite2.lookup(self.src).country
            self.whois_country = str(pycountry.countries.get(alpha_2=self.whois_code).name).split(",")[0]
        else:
            self.whois = 'UNKNOWN ADDRESS'
            self.whois_country = 'UNKNOWN COUNTRY'
            self.src = 'UNKNOWN ADDRESS';
            self.dst = 'UNKNOWN ADDRESS';
            self.dstport = '';


    """
    function: insert into table
    things needed: db_host, db_name, db_user, db_pass, debug*
    debug* = optional
    part I.4/5
    """
    def insertIntoTable(self, StringCSV):
        self.StringCSV = StringCSV
        self.readStringCSV(self.StringCSV)
        ### print self.timestamp, self.sig_id, self.msg, self.proto
        ### print self.src, self.srcport, self.dst, self.dstport, self.ethsrc, self.ethdst

        if self.src != 'UNKNOWN ADDRESS':
            self.sql_query = "INSERT INTO `snort_history`"
            self.sql_query += "(`date`, `signature`, `sigid`, `protocol`, `source`, "
            self.sql_query += "`whois`, `country`, `destination`, `macsrc`, `macdst`) "
            self.sql_query += "VALUES ('"+self.timestamp+"','"+self.msg+"','"+self.sig_id+"','"
            self.sql_query += self.proto+"','"+self.src+":"+self.srcport+"','"+self.whois+"','"
            self.sql_query += self.whois_country+"','"+self.dst+":"+self.dstport+"','"
            self.sql_query += self.ethsrc+"','"+self.ethdst+"');"
        else:
            self.sql_query = ''
        ### Open database connection
        self.db_connection = mysql.connector.connect(host=self.db_host, user=self.db_user, password=self.db_pass, database=self.db_name)

        ### Prepare a cursor object using cursor() method
        self.cursor = self.db_connection.cursor()

        ### Execute SQL query using execute() method.
        self.cursor.execute(self.sql_query)

        ### Make sure data is committed to the database
        self.db_connection.commit()

        ### Close MySQL connection
        self.cursor.close()
        self.db_connection.close()
        if debug:
            print "-----------------------------------------------"
            print "insertIntoTable():"
            print "-----------------------------------------------"
            print " [debug]", self.sql_query


    """
    function: check the differences
    things needed: log_old=file1, log_veryold=file2, debug*
    *debug = optional
    part I.5/5
    """
    def differences(self):
        if debug:
            print "-----------------------------------------------"
            print "differences():"
            print "-----------------------------------------------"
            print " [debug]"
        self.open_old = open(self.log_old)
        self.open_veryold = open(self.log_veryold)
        ### Read first line from each file
        self.old_line = self.open_old.readline()
        self.veryold_line = self.open_veryold.readline()
        ### Initialize counter for line number
        self.line_no = 1

        ### Loop if either file1 or file2 has not reached EOF
        while self.old_line != '' or self.veryold_line != '':
            ### Strip the newlines from begining and the end of string
            self.old_line = self.old_line.rstrip()
            self.veryold_line = self.veryold_line.rstrip()

            ### Compare the lines from both file
            if self.old_line != self.veryold_line:
                ### If a line does not exist on file2 then mark the output with + sign
                if self.veryold_line == '' and self.old_line != '':
                    self.defference_between_old_and_veryold = self.old_line
                    self.insertIntoTable(self.defference_between_old_and_veryold)
                    if debug:
                        print "++", self.defference_between_old_and_veryold

            ### Read the next line from the file
            self.old_line = self.open_old.readline()
            self.veryold_line = self.open_veryold.readline()
            ### Increment line counter
            self.line_no += 1

        ### Close the files
        self.open_old.close()
        self.open_veryold.close()
        if debug:
            print "-----------------------------------------------"



###################################################
### @call the functions
###################################################
LogToDB(
    current_log_file,
    old_log_file,
    veryold_log_file,
    db_host,
    db_name,
    db_user,
    db_pass,
    debug
)
