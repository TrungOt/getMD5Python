import os
import os.path as ischeck

#lấy values cho dict
listDirValues = []
listFileValue = []
total1 = 0
total2 = 0
total3 = 0
print("Nhập đường đẫn: ", end="")
path = input()
checkNull = os.access(path, os.F_OK)

#Đệ quy
def Get_dir(source):
    global total1, total2
    path_dir = os.listdir(source)
    for i in range(len(path_dir)):
        sFullPath = source + "\\" +  path_dir[i]
        isFile = ischeck.isfile(sFullPath)
        if isFile == True:
            print("Files: ", end="")
            print(path_dir[i])
            total1 += 1  
        else:
            Get_dir(sFullPath)
            print("Path-Folder: ", end="")
            print(source)
            total2 +=1
    print("số lượng folders: " + str(total1))
    print("số lượng files: " + str(total2))        

#Không đệ quy
def Get_all_files(source):
    global total1, total2, total3
    list_path = os.listdir(source)
    for i in range(len(list_path)):
        sFullPath = source + "\\" +  list_path[i]
        isFile = ischeck.isfile(sFullPath)
        if isFile == True:
            listFileValue.append(list_path[i])
            temp = listFileValue.pop()
            print("Files: " + temp)
            total1 += 1
        else:
            listDirValues.append(list_path[i])
            subTemp = listDirValues.pop()
            for sfullPath2, subTemp, filesname in os.walk(sFullPath):
                print("Path-Folder : " + sfullPath2)
                total2 += 1
                for item in filesname:
                        print("sub-Files: " + item)
                        total3 += 1
    print("số lượng folder: " + str(total2))
    print("số lượng files: " + str(total1 + total3))
    
if checkNull == True:
    print("Đường dẫn hiện tại: ", end="")
    linkpath = os.getcwd()
    linkpath = path
    print(linkpath)

    #Get_dir(linkpath)          # Đệ quy
    Get_all_files(linkpath)     # Không đệ quy
   
else:
    print("Cần nhập đúng đường dẫn.\n")
    #D:\TEST
    #D:\TEST\BaiTapListSetsTupleDict
    