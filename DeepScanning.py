import hashlib
import os
#Global Variable

malware_hashes = list(open("hashes2.unibit","r").read().split('\n'))
virusinfo = list(open("virusinfo2.unibit","r").read().split('\n'))

#Get Hash of File

def sha256(filename):
    try:
        with open(filename, 'rb') as f:
            bytes = f.read()
            sha256hash = hashlib.sha256(bytes).hexdigest()

            f.close()
            # print("sha256 hash")

        return sha256hash
    except:
        return 0

#Malware Detection by Hash Algorithm
def malware_detection(pathoffile):
    global malware_hashes
    global virusinfo2

    hash_malware_chck = sha256(pathoffile)
    counter = 0

    for i in malware_hashes:
        if i == hash_malware_chck:
            return virusinfo2(counter)
        counter += 1

    return 0;

# Malware Detection in Folder
virusName = []

def folderScanner():

    #Get the list of files in the directory 
    dir_list = list()
    path = (r"C:\Antivirus\keylog.zip")
    dir_list = os.listdir(path)
    
    fileN = " "

    for i in dir_list:
        fileN = path + "\\"+i
        if malware_detection(fileN) !=0:
            virusName.append(malware_detection(fileN) +" ::file :: " + i)

folderScanner()

print(virusName)


#IN dEPTH Algo for scanning folder _ folderScan
virusname = []

def folderScanner():
    #getting the list of files in directory tree at given path
    dir_list = list()
    for(dirpath , dirnames , filenames) in os.walk("C:\Antivirus\keylog.zip"):
        dir_list += [os.path.join(dirpath,file) for file  in filenames]

##Checking the hash in the respective folder if found append the virusname[] list 
    for i in dir_list:
        print(i)
        if malware_detection(i) != 0:
            virusname.append(malware_detection(i)+" ::file ::"+i)

folderScanner()
print(virusname)



# VirusRemover

virusname = []
virusPath = []

def virusScanner(path):
    #getting the list of files in directory tree at given path
    dir_list = list()
    for(dirpath , dirnames , filenames) in os.walk("path"):
        dir_list += [os.path.join(dirpath,file) for file  in filenames]

##Checking the hash in the respective folder if found append the virusname[] list 
    for i in dir_list:
        print(i)
        if malware_detection(i) != 0:
            virusname.append(malware_detection(i)+" ::file ::"+i)
            virusPath.append(i)

#Virus Remover
def virusRemover(path):
    virusScanner(path)
    if virusPath:
        for i in virusPath:
            os.remove(i)
    else:
        return 0
    
virusRemover("C:\Antivirus\keylog.zip")




#####Temp File Remover #####

def justFileRemover():
    ##Junk files Remover
    #windows key + r
    temp_list = list()

    username = os.environ.get('USERNAME').upper().split(' ')

    print(username)

    for (dirpath,dirnames,filenames) in os.walk("C:\Windows\Temp".format(username[0])):    #passing string under variable .format(username[0] index)
        temp_list += [os.path.join(dirpath,file) for file in filenames]
        temp_list += [os.path.join(dirpath,file) for file in dirnames]


    # for (dirpath,dirnames,filenames) in os.walk(""):
    #     temp_list += [os.path.join(dirpath,file) for file in filenames]
    #     temp_list += [os.path.join(dirpath,file) for file in dirnames]

    # for (dirpath, dirnames, filenames) in os.walk("C:\Windows\Prefetch"):
    #     temp_list += [os.path.join(dirpath,file) for file in filenames]
    #     temp_list += [os.path.join(dirpath,file) for file in dirnames]
        
    print(temp_list)
    
    if temp_list:

        try:
            for i in virusPath:
                os.rmdir(i)
        except:pass

    else:
        return 0; 
        

def rambooster():

    #cmd : tasklist   ##printing the tasklist  
    # list of normally using software [] into the tasklist 

    tasklist = ["notepad.exe"]    ##list of software to close in  the tasklist

    #Task Kill
    for i in tasklist:
        try:
            os.system("taskkill /f /im {}".format(i))
        
        except:
            return 0

rambooster()







            



































        
#https://www.youtube.com/watch?v=H0fg-6PUHhw&list=PLkzUkNupwT3S-lwWGfG6D5Xs2-hKuxXT2&index=9