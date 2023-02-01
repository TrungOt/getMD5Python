__author__ = 'anhdvd@bkav.com'

import calendar
import json
import logging
from ntpath import join
import os
import sqlite3 as lite
from datetime import date, datetime
from shutil import copyfile
from logging.handlers import RotatingFileHandler

import re
import sys
import threading
import time
import sys
import requests
import tlsh
import keyboard

from requests.sessions import session

if sys.version_info[0] == 3:
    import urllib.request as urllib
else:
    import urllib
import shutil

# Insert your API here
API_KEY = 'a50869dfe068d7f1a1d5d81e617186e23e1cef6d95d8ac11d6f0594f883f6877'
API_URL = ('https://www.virustotal.com/vtapi/v2/file/distribution'
           '?after=%s&limit=%s&apikey=%s&reports=true')
API_BATCH_SIZE = 1000
DB_VIRUS_PATH = 'virus.db'
DB_TLSH_PATH = 'TLSH.db'
TLSH_SCORE = 12

NONE_TYPE = "NONE_TYPE"

LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig( level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',handlers=[
                    logging.FileHandler(filename="filelog.log",mode='a'),
                    logging.StreamHandler()])
                    #stream=sys.stdout)

# logger = logging.getLogger('my_logger')
# handler = RotatingFileHandler('my_log.log', maxBytes=15*1024*1024, backupCount=1000)
# logger.addHandler(handler)

# def writelog(log):
#     logToFile = '{}     {}'.format(datetime.today().strftime("%d/%m/%Y %H:%M:%S"), log)
#     logger.warning(logToFile)

DownloadPath = ''
g_md5exists = []
g_md5Success = []
g_countDBMD5old=0
g_countDBMD5new=0
g_KeyboardStroke = False
g_threadslist = []
g_list_tlsh = []
g_total_file_download = 0
g_total_file_save = 0
g_total_file_delete = 0
g_totalFileError = 0

class VTSampleDownload:
    def __init__(self, key):
        self.api_key = key
        self.type = NONE_TYPE

    def get_download_candidates(self, after=0, limit=API_BATCH_SIZE):
        try:
            dt_object = datetime.fromtimestamp(int(after)/1000.0)
            logging.info('Get Candidates, timestamp: ' + str(after) + ' - ' + dt_object.strftime("%d/%m/%Y %H:%M:%S") + ', limit: ' + str(limit))
            http_proxy = "http://proxybsh.bkav.com:3128"
            https_proxy = "http://proxybsh.bkav.com:3128"
            ftp_proxy = "ftp://proxybsh.bkav.com:3128"

            proxyDict = {
                "http": http_proxy,
                "https": https_proxy,
                "ftp": ftp_proxy
            }
            response = requests.get(API_URL % (after, limit, self.api_key), proxies=proxyDict)
            response = response.text
            # f = open("json.json", 'w')
            # f.write(str(response))
            # f.close()
        except Exception as ex:
            logging.info(f'Get Candidates error: {ex}')
            time.sleep(2)
            return
        try:
            candidates = json.loads(response)
            logging.info('Total json in Candidates: ' + str(len(candidates)))
        except Exception as ex:
            logging.info(f'Load json in Candidates error: {ex}')
            time.sleep(5)
            return
        return candidates

    def current_after(self):
        """Retrieves the current after value from persistent storage.

        VirusTotal's distribution API is based on a sliding window approach with and
        after parameters that allows you to paginate over all the files submitted
        after a given timestamp. The first time this script is launched the current
        after is read from disk.

        Returns:
          Last after value stored in disk, as a string. If the script was never
          launched before or the script's memory was deleted it will return the
          current timestamp minus 3 hours.
        """
        after = ''
        try:
            if os.path.exists('timestamp.memory'):
                # Retrieve the stored after pointer.
                with open('timestamp.memory', 'r') as memory:
                    after = memory.read().strip()

            if not re.match('[0-9]+$', after):
                # We do not know where we were at, just fix after to be 3 hours before the
                # current GMT epoch.
                after = '%s' % ((calendar.timegm(time.gmtime()) - 3 * 3600) * 1000)
        except Exception as ex:
            logging.info(f'Error after: {ex}')
        return after

# Kiểm tra phải virus linux không
def check_ELF_and_Download(candidate):
    global g_threadslist
    countVirus = 0
    countJson = 0
    len_candi=0

    if candidate != None:
        len_candi = len(candidate)
    else:
        #print("Khong co candi")
        f = open("timestamp.memory", 'w')
        f.write("0")
        f.close()
        return 0

    for i in candidate:
        if countJson == len_candi-1:
            f = open("timestamp.memory", 'w')
            f.write(str(i['timestamp']))
            f.close()

        # check virus va json neu du so luong
        countJson += 1

        # check file elf
        virus_type = i['type']
        if (type(virus_type) != str):
            continue
        
        virus_type_lowercase = virus_type.lower()
        if 'elf' == virus_type_lowercase:
            try:
                # check Kaspersky
                Kaspersky = i['report']['Kaspersky']
                if Kaspersky[0] != None:
                    md5 = str(i['md5'])
                    linkDownFile = str(i['link'])
                    if (len(md5) <= 0) or (len(linkDownFile) <= 0):
                        logging.info('Error Md5 or LinkDownFile is NULL')
                        continue
                    
                    countVirus += 1
                    
                    # save file virus
                    iThread = threading.Thread(target=DownloadFile,args=(linkDownFile, md5),daemon=True)
                    g_threadslist.append(iThread) 
                    iThread.start()
                    if len(g_threadslist)>=10:
                        for threads in g_threadslist:
                            threads.join()
                        g_threadslist.clear()
                    time.sleep(0.5)
            except Exception as ex:
                logging.info('check_ELF_and_Download Error: ' + str(ex))
                continue

    logging.info('Number Virus/Json in candidate: {}/{}'.format(countVirus, countJson))
    return

def DownloadFile(urldownload, md5):
    global g_total_file_download
    global g_total_file_delete
    global g_total_file_save
    global g_totalFileError
    filename = str(DownloadPath + "/" + md5)

    if len(urldownload) == 0:
        logging.info('DownloadFile Urldownload NULL')
        return

    try:
        #logging.info('Download file: ' + filename)
        http_proxy = "http://proxybsh.bkav.com:3128"
        https_proxy = "http://proxybsh.bkav.com:3128"
        ftp_proxy = "ftp://proxybsh.bkav.com:3128"
        proxyDict = {
            "http": http_proxy,
            "https": https_proxy,
            "ftp": ftp_proxy
        }
        response = requests.get(url=urldownload, proxies=proxyDict)
        if not os.path.isfile(md5):
            f = open(filename, 'wb')
            f.write(response.content)
            f.close()
            g_total_file_download += 1

    except Exception as ex:
        logging.info("File: " + md5 + " Not Dowloaded with Error: " + str(ex) + ".Link file: " + str(urldownload))
        g_totalFileError += 1
        return

    saveFileInfoToDb(filename, urldownload)

    if CheckTLSHInList(filename):
        backupFile(filename, md5, urldownload)
        g_total_file_delete += 1
    else:
        g_total_file_save += 1
    
    return

# return True if exist, error
# return False if not exist
def CheckTLSHInList(filename):
    global g_list_tlsh
    global g_totalFileError

    try:
        current_tlsh = tlsh.hash(open(filename, 'rb').read())

        if (current_tlsh == "TNULL"):
            logging.info("TLSH of file: {}, error: TLSH = TNULL".format(filename))
            g_totalFileError += 1
            return True

        for tlsh_item in g_list_tlsh:
            score = tlsh.diff(current_tlsh, tlsh_item)
            if (score <= TLSH_SCORE):
                #logging.info("Score: " + str(score) + ".File exist: " + filename)
                return True

        g_list_tlsh.append(current_tlsh)

    except Exception as ex:
        logging.info("CheckTLSH of file: " + filename + " exception: " + str(ex))
        g_totalFileError += 1
        return True
    
    return False

def backupFile(filePath, md5, urldownload):
    today = date.today().strftime("%d_%m_%Y")
    backupFolder = "BackupFolder_{}".format(today)
    if not os.path.exists(backupFolder):
        os.makedirs(backupFolder)

    filePathCheck = backupFolder + "/" + md5
    if os.path.exists(filePathCheck):
        os.remove(filePath)
    else:
        os.rename(filePath, backupFolder + "/" + md5)

    md5FilePath = backupFolder + "/ELFmd5.txt"
    log = "Backup file: {}, md5: {}, link download: {}\n".format(filePath, md5, urldownload)
    f = open(md5FilePath, 'a')
    f.write(log)
    f.close()

def AddMd5ToDB(md5):
    con = None
    global g_countDBMD5old
    global g_countDBMD5new
    temp=0

    if (len(md5) <= 0):
        logging.info('Error md5 is NULL')
        return 0

    virusname = 'Trojan.Linux.'+md5[0:5]
    try:
        con = lite.connect(DB_VIRUS_PATH)
        with con:
            cur = con.cursor()
            # Dem so luong
            if g_countDBMD5old == 0:
                cur.execute('select count("MD5") FROM tbVirus')
                g_countDBMD5old = cur.fetchone()[0]
                g_countDBMD5new = g_countDBMD5old
            cur.execute("SELECT MD5 FROM tbVirus WHERE MD5='" + md5 + "';")
            if cur.fetchmany():  # ton tai md5 nay
                #logging.info('MD5 da ton tai: ' + md5)
                g_md5exists.append(md5)
                return 2
            else:
                cur.execute('INSERT INTO tbVirus VALUES("' +
                            virusname + '","' + md5 + '");')
                temp = g_countDBMD5new
                g_countDBMD5new = cur.lastrowid
                if(g_countDBMD5new==temp):
                    logging.info('Error Add MD5: '+ md5)
                else:
                    #print('Suscess Add MD5: '+ md5)
                    g_md5Success.append(md5)
    except lite.Error as ex:
        logging.info('Error SQLite ' + str(ex))
        return 0
    return 1

def CheckKeyboardStroke():
    global g_KeyboardStroke
    keyboard.wait('ctrl+shift+e')
    logging.info("Download Virus Exit........................................!")
    g_KeyboardStroke=True

def initTLSHdb():
    connection = None
    try:
        connection = lite.connect(DB_TLSH_PATH)
        TLSHdb = connection.cursor()
        TLSHdb.execute('CREATE TABLE IF NOT EXISTS tblTLSH (FileName TEXT, TLSH TEXT, LinkDownFile TEXT)')
        connection.commit()
    except lite.Error as ex:
        logging.info('Error To Create tblTLSH Database: ' + str(ex))
        return False
    return True

def loadTLSHFromDb():
    global g_list_tlsh
    connection = None
    try:
        connection = lite.connect(DB_TLSH_PATH)
        TLSHdb = connection.cursor()
        TLSHdb.execute('SELECT TLSH FROM tblTLSH')
        row = TLSHdb.fetchall()
        for item in row:
            g_list_tlsh.append(item[0])
    except lite.Error as ex:
        logging.info('Error Load TLSH From Database: ' + str(ex))

def saveFileInfoToDb(fileName, linkDownFile):
    connection = None
    try:
        current_tlsh = tlsh.hash(open(fileName, 'rb').read())
        if (current_tlsh == "TNULL"):
            logging.info("saveFileInfoToDb - Get TLSH = TNULL, FileName: {}, Link: {}".format(fileName, linkDownFile))
            return
    except Exception as ex:
        logging.info('saveFileInfoToDb - Get TLSH Error: {}, FileName: {}, Link: {}'.format(str(ex), fileName, linkDownFile))
        return

    try:
        connection = lite.connect(DB_TLSH_PATH)
        TLSHdb = connection.cursor()
        sqlCmd = "INSERT INTO tblTLSH (FileName, TLSH, LinkDownFile) VALUES ('{}', '{}', '{}')".format(fileName, current_tlsh ,linkDownFile)
        TLSHdb.execute(sqlCmd)        
        connection.commit()
    except lite.Error as ex:
        logging.info('Error Save TLSH To Database: ' + str(ex))    

def main():
    # Khoi tao
    print("1.Download Virus")
    print("2.Add MD5 to DB")
    ioptions=0
    while True:
        ioptions = input("Enter Your Option: ")
        if ioptions == '1' or ioptions=='2':
            break
        else : print("Enter Your Option Again: ")

    global DownloadPath
    DownloadPath = 'Download'
    AddedToDBPath = 'AddedToDB'
    if not os.path.exists(AddedToDBPath):
        os.makedirs(AddedToDBPath)
        logging.info('Create Folder AddedToDB')

# **************************************Start**************************************
    
    # Xóa nếu file MD5 > 5000 kb
    # if os.path.isfile('ELFmd5.txt'):
    #     if (os.path.getsize('ELFmd5.txt')//1000) > 5000:
    #         os.remove('ELFmd5.txt')

    # Xóa log nếu file log > 2000kb
    # today = datetime.today()
    # if os.path.isfile('filelog.log'):
    #     if (os.path.getsize('filelog.log')//1000) > 1:
    #         sFileName = "filelog_{}.log".format(today.strftime("%Y%m%d%H%M%S"))
    #         os.rename('filelog.log', sFileName)
    
    sessionjson = 500

    print("Help Vietnamese ->  Readme.txt")
    logging.info(f'------------------------- Start {datetime.today().strftime("%d/%m/%Y - %H:%M:%S")} ------------------------')
    if ioptions == '1':
        logging.info('--------------------------SELECT DOWNLOAD VIRUS--------------------------')
        if not os.path.exists(DownloadPath):
            os.makedirs(DownloadPath)
            logging.info('Create Folder Download')
        
        if initTLSHdb() == False:
            logging.info('False To Create Database TLSH.db')
            return
        
        loadTLSHFromDb()
        
        # Start download
        vt_download = VTSampleDownload(
            "b39c0fb1c56dd959f6b217c24a9c43e27e3a0b7192fd4e9eb39e7cbbbab9cb14")
        # thread keyboard để dừng vòng while
        threading.Thread(target=CheckKeyboardStroke).start()
        while(True):
            after = vt_download.current_after()
            candidate = vt_download.get_download_candidates(after, sessionjson)
            check_ELF_and_Download(candidate)
            logging.info('Total file Save/Download: {}/{}. Backup: {}. Error: {}'.format(g_total_file_save, g_total_file_download, g_total_file_delete, g_totalFileError))
            if g_KeyboardStroke==True:
                for t in g_threadslist:
                    t.join()
                break
            time.sleep(1)
        logging.info('*********** Finish Download Virus! ************')
        logging.info('Total file Download: '+str(g_total_file_download))
        logging.info('Total file save: '+str(g_total_file_save))
        logging.info('Total file backup: '+str(g_total_file_delete))

    if ioptions=='2':
        try:
            logging.info('------------------------SELECT ADD TO DB-------------------------')
            list_dir = os.listdir(DownloadPath) # get filename tong folder Download

            list_tlsh = []
            list_md5 = []
            nTotalFile = 0
            nDeleteFile = 0

            for nameMD5 in list_dir:
                filePath = DownloadPath + '/' + nameMD5
                current_tlsh = tlsh.hash(open(DownloadPath + '/' + nameMD5, 'rb').read())

                if (current_tlsh == "TNULL"):
                    logging.info('Add to db - tlsh = null, file name: ' + filePath)
                    backupFile(filePath, nameMD5, '')
                    #os.remove(DownloadPath + '/' + nameMD5)
                    continue

                if (nTotalFile == 0):
                    list_tlsh.append(current_tlsh)
                    list_md5.append(nameMD5)
                    nTotalFile += 1
                    continue
                
                bExist = False
                for tlsh_item in list_tlsh:
                    score = tlsh.diff(current_tlsh, tlsh_item)
                    if (score <= TLSH_SCORE):
                        bExist = True
                        backupFile(filePath, nameMD5, '')
                        #os.remove(DownloadPath + '/' + nameMD5)
                        print("Add to DB. Score: " + str(score) + ". Backup file: " + nameMD5)
                        nDeleteFile += 1
                        break
                
                if (bExist == False):
                    list_tlsh.append(current_tlsh)
                    list_md5.append(nameMD5)
                
                nTotalFile += 1

            print("Backup file/Total file: " + str(nDeleteFile) + "/" + str(nTotalFile))

            for nameMD5 in list_md5:
                iresult = AddMd5ToDB(nameMD5)
                filePath = DownloadPath + '/' + nameMD5
                if iresult==1:
                    copyfile(DownloadPath + '/' + nameMD5, AddedToDBPath + '/' + nameMD5)
                    os.remove(DownloadPath + '/' + nameMD5)
                    logging.info(f'Copy File and Delete: {nameMD5}')
                elif iresult==2:
                    os.remove(DownloadPath + '/' + nameMD5)
                    logging.info(f'File exist in DB, Delete File: {filePath}')
            
            logging.info('*********** Finish Add To DB! ************')
            logging.info('MD5 Add Succesfuly: ')
            for i in g_md5Success:
                logging.info("\t\t\t\t\t"+i)
            logging.info('MD5 Already Exists: ')
            for i in g_md5exists:
                logging.info("\t\t\t\t\t"+i)
            logging.info('Total MD5 Old: '+str(g_countDBMD5old))
            logging.info('Total MD5 New: '+str(g_countDBMD5new))
            logging.info('Total MD5 Added To DB: '+str(g_countDBMD5new - g_countDBMD5old))
        except Exception as ex:
            logging.info('Add md5 to DB Error: ' + str(ex))

#    os.system('PAUSE')
main()
