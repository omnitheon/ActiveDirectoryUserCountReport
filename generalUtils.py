import datetime
import io
#Return current time
def currT():
    return str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])

def end(start):#Takes the start time and outputs when the script started and ended
    print("[*]-{}...Started the Script...\n[*]-{}...Script is exiting...".format(start,currT()))

#Beep the user for input
def beep():
    print("\a",end="")

def writeToDisk(outfileName,data):
    with io.open(outfileName, "w", encoding="utf-8") as f:
        f.write(str(data))
        f.close()

def getFlatFileString(path):
    return open(path,"r").read()

def getReadLines(path):
    return open(path,'r').readlines()  

def stripInfile(infileList):
    for rowI in range(len(infileList)):
        currentRow = infileList[rowI].strip()
        infileList[rowI] = currentRow 
    return infileList

