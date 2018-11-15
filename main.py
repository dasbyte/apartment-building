import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

dataSave = "1F26D330" 

#dataSave = getpass.getpass(" Encyption Key: ") #Uncomment this if you wish to use your own key

def encrypt(key, filename):

	chunksize = 65536
	outputFile = "(encrypted)"+filename
	filesize = str(os.path.getsize(filename)).zfill(16)
	IV = Random.new().read(16)

	encryptor = AES.new(key, AES.MODE_CBC, IV)

	with open(filename, "rb") as infile:
		with open(outputFile, "wb") as outfile:
			outfile.write(filesize.encode("utf-8"))
			outfile.write(IV)
			
			while True:
				chunk = infile.read(chunksize)
				
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk += b" " * (16 - (len(chunk) % 16))

				outfile.write(encryptor.encrypt(chunk))


def decrypt(key, filename):

	chunksize = 65536
	outputFile = filename[11:]
	
	with open(filename, "rb") as infile:
		filesize = int(infile.read(16))
		IV = infile.read(16)

		decryptor = AES.new(key, AES.MODE_CBC, IV)

		with open(outputFile, "wb") as outfile:
			while True:
				chunk = infile.read(chunksize)

				if len(chunk) == 0:
					break

				outfile.write(decryptor.decrypt(chunk))
			outfile.truncate(filesize)


def getKey(password):

	hasher = SHA256.new(password.encode("utf-8"))
	return hasher.digest()

import random
import pandas as pd
import getpass

usersColumns = ['Username','Password','First Name','Middle Name','Last Name','Phone Number','Licence Plate','Apartment Floor','Apartment Number','Rent Due','Role']
aptsColumns  = ['Apartment Floor','Apartment Number','Rent','Lease Expiration Date','Username','Repairs Needed']

def main():
    
    users, apts = importAll()
    saveAll(users,apts)
    runMain = True
    while runMain is True:
        runMain = securityCheck(users,apts)
        users, apts = importAll()

def importAll():

    def importUsers(): #Looks for username file and if it is there decrypts it with provided key
        
        try:
            filename = '(encrypted)users.csv'
            password = str(dataSave)
            decrypt(getKey(password), filename)
            users = pd.read_csv('users.csv')
            os.remove("users.csv")

        except:
            data = [['RENTER','password','renter','renter','renter',"empty","empty",0,0,0,'RENTER'],['MAINTENANCE','password','maintenance','maintenance','maintenance',"empty","empty",0,0,0,'MAINTENANCE'],['MANAGER','password','manager','manager','manager',"empty","empty",0,0,0,'MANAGER'],['ADMIN','password','admin','admin','admin',"empty","empty",0,0,0,'ADMIN']]
            users = pd.DataFrame(data,columns = usersColumns)
            
        return users

    def importApts(): #Looks for apartments file and if it is there decrypts it with provided key

        try:
            filename = '(encrypted)apartments.csv'
            password = str(dataSave)
            decrypt(getKey(password), filename)
            apts = pd.read_csv('apartments.csv')
            os.remove("apartments.csv")

        except:
            data = [[1,3,500,"empty","empty","N"]]
            apts = pd.DataFrame(data,columns = aptsColumns)

        return apts

    users = importUsers()
    apts = importApts()

    return users,apts
    
def saveAll(users, apts): #Takes current data for users and apartments then encrypts them with provided key

    password = dataSave

    def saveUsers(users):
        
        users.to_csv("users.csv", index=False, encoding='utf-8')
            
        filename = 'users.csv'
        encrypt(getKey(password), filename)

        os.remove("users.csv")

    def saveApts(apts):

        apts.to_csv("apartments.csv", index=False, encoding='utf-8')

        filename = 'apartments.csv'
        encrypt(getKey(password), filename)

        os.remove("apartments.csv")

    saveUsers(users)
    saveApts(apts)
    
    
#User Login
def securityCheck(users,apts): #Login for user then upon type of user provides user with a menu

    print(apts,"\n",users) #Used for ease of understanding program would be removed in true program

    def userLogin(users):
        
        _User = input(" Username: ").strip().upper()
 
        _Password = getpass.getpass(" Password: ").strip()

        try:
            index = users.loc[users['Username'] == _User].index[0]
            try:
                if users.iloc[index][1] == _Password:
                    print(" Passed")
                    return index, _User
                else:
                    return False
            except:
                input("\n Error\n\n Back to Menu: ")
        except:
            input("\n Error\n\n Back to Menu: ")

        return False
        

    def renterMenu(users,apts,userIndex,_User):
        
        
        renterMenuInput = input("\n Renter Menu\n\n" +
                                " - 1 Current Rent Due\n" +
                                " - 2 Pay Rent\n" +
                                " - 3 Lease Expiration\n" +
                                " - 4 Request Repairs\n" +
                                " - 5 Logout\n\n - ")

        if renterMenuInput == "1":

            try:
                input("\n " + str(users.iloc[index][9]) + "\n\n Back to Menu: ")
            except:
                input("\n Error\n\n Back to Menu: ")
            
            return True
            
        elif renterMenuInput == "2":

            try:
                input("\n Amount Due: " + str(users.iloc[index][9]) + "\n\n Pay Now: ")

                #Insert Payment System

                print("\n Payment Successful")
            except:
                input("\n Error\n\n Back to Menu: ")
            
            return True

        elif renterMenuInput == "3":

            try:
                aptIndex = apts.loc[apts['Username'] == _User].index[0]
                input("\n " + str(apts.iloc[index][3]) + "\n\n Back to Menu: ")
            except:
                input("\n Error\n\n Back to Menu: ")

            return True
            
        elif renterMenuInput == "4":

            try:
                aptIndex = apts.loc[apts['Username'] == _User].index[0]
                apts.at[aptIndex, "Repairs Needed"] = "Y"
                saveAll(users, apts)
                input("\n Repairs Requested!\n\n Back to Menu: ")
            except:
                input("\n Error\n\n Back to Menu: ")

            return True
            
        elif renterMenuInput == "5":

            try:
                confirm = input("\n Confirm Logout(Y/N): ").upper()
                if confirm == "Y":
                    return False
                else:
                    pass
                    
            except:
                input("\n Error\n\n Back to Menu: ")

            return True
        
        else:
            return True
                           
        

    def maintenanceMenu(users,apts,userIndex,_User):

        maintenanceMenuInput = input("\n Maintenance Menu\n\n" +
                                " - 1 List Repair Requests\n" +
                                " - 2 Finish Repairs\n" +
                                " - 3 Logout\n\n - ")

        if maintenanceMenuInput == "1":
            
            try:
                
                results = apts.loc[apts['Repairs Needed'] == ('Y')].index

                if results == []:
                    
                    print("\n No Repairs Needed!\n\n Back to Menu: ")
                    
                else:
                    
                    for x in results:
                        print("\n Floor: " + str(apts.iloc[x][0]) + " - Number: " + str(apts.iloc[x][1]))
                    
            except:
                
                input("\n No Repairs Needed!\n\n Back to Menu: ")

            return True

        elif maintenanceMenuInput == "2":
            
            try:
                inputFloor = input(" Apartment Floor: ")
                inputNumber = input(" Apartment Number: ")
                results = apts.loc[apts['Apartment Floor'] == (int(inputFloor))].index
                for x in results:
                    if apts.iloc[x][1] == (int(inputNumber)):
                        
                        apts.at[x, "Repairs Needed"] = "N"

                        input("\n Repairs Complete!\n\n Back to Menu: ")
                        saveAll(users, apts)
                
                
            except:
                input("\n Error\n\n Back to Menu: ")

            return True

        elif maintenanceMenuInput == "3":

            try:
                confirm = input("\n Confirm Logout(Y/N): ").upper()
                if confirm == "Y":
                    return False
                else:
                    pass
                    
            except:
                input("\n Error\n\n Back to Menu: ")

            return True

        else:
            return True

    def managerMenu(users,apts,userIndex,_User):

        managerMenuInput = input("\n Manager Menu\n\n" +
                                " - 1 Add Apartment\n" +
                                " - 2 Remove Apartment\n" +
                                " - 3 Change Rent\n" +
                                " - 4 Lease Apartment\n" +
                                " - 5 Cancel Lease\n" +
                                " - 6 Available Apartments\n" +
                                " - 7 Logout\n\n - ")

        if managerMenuInput == "1":

            try:
                aF = input(" Apartment Floor: ")
                aN = input(" Apartment Number: ")
                rT = float(input(" Rent: "))
                
                
                data = [[aF,aN,rT,"empty","empty","N"]]
                df = pd.DataFrame(data,columns = aptsColumns)
                apts = apts.append(df, ignore_index=True)

                saveAll(users, apts)
                
            except:
                input("\n Error\n\n Back to Menu: ")

            return True

        elif managerMenuInput == "2":
            aF = input(" Apartment Floor: ")
            aN = input(" Apartment Number: ")

            confirm = input(" Confirm Deletion of Floor: " + aF + " Number: " + aN + " - (Y/N): ").upper()

            if confirm == 'Y':
                try:
                    results = apts.loc[apts['Apartment Floor'] == (int(aF))].index
                    for x in results:
                        
                        if apts.iloc[x][1] == (int(aN)):
                            apts = apts.drop(apts.index[x])

                            saveAll(users, apts)
                    
                except:
                    input("\n Error\n\n Back to Menu: ")

            return True

        elif managerMenuInput == "3":

            aF = input(" Apartment Floor: ")
            aN = input(" Apartment Number: ")

            try:
                nR = float(input(" Rent Amount: "))
                results = apts.loc[apts['Apartment Floor'] == (int(aF))].index
                for x in results:
                            
                    if apts.iloc[x][1] == (int(aN)):
                        apts.at[x, "Rent"] = nR

                        saveAll(users, apts)
                        
            except:
                input("\n Error\n\n Back to Menu: ")

            return True

        elif managerMenuInput == "4":

            aF = input(" Apartment Floor: ")
            aN = input(" Apartment Number: ")
            uR = input(" Username: ").strip().upper()
            lE = input(" Lease Expiration Date(M/D/Y): ")

            try:
                results = apts.loc[apts['Apartment Floor'] == (int(aF))].index
                for x in results:
                    if apts.iloc[x][1] == (int(aN)):

                        apts.at[x, "Username"] = uR
                        apts.at[x, "Lease Expiration Date"] = str(lE)
                        
                        saveAll(users, apts)
                        
            except:
                input("\n Error\n\n Back to Menu: ")

            return True

        elif managerMenuInput == "5":

            aF = input(" Apartment Floor: ")
            aN = input(" Apartment Number: ")

            try:
                results = apts.loc[apts['Apartment Floor'] == (int(aF))].index
                for x in results:
                    
                    if apts.iloc[x][1] == (int(aN)):
                            
                        apts.at[x, "Username"] = "empty"
                        apts.at[x, "Lease Expiration Date"] = "empty"

            except:
                input("\n Error\n\n Back to Menu: ")

            try:
                
                results = users.loc[users['Apartment Floor'] == (int(aF))].index

                for x in results:

                    if int(users.iloc[x][8]) == (int(aN)):
                        
                        users.at[x, "Apartment Floor"] = 0
                        users.at[x, "Apartment Number"] = 0

                        saveAll(users, apts)

            except:
                input("\n Error\n\n Back to Menu: ")

            return True

        elif managerMenuInput == "6":
            
            try:
                results = apts.loc[apts['Username'] == "empty"].index

                for x in results:
                    print(" Floor: " + str(apts.iloc[x][0]) + " Number: " + str(apts.iloc[x][1]))

            except:
                input("\n Error\n\n Back to Menu: ")

            return True
        
        elif managerMenuInput == "7":

            try:
                confirm = input("\n Confirm Logout(Y/N): ").upper()
                if confirm == "Y":
                    return False
                else:
                    pass
                    
            except:
                input("\n Error\n\n Back to Menu: ")

            return True

        else:
            return True

                

    def adminMenu(users,userIndex,_User):

        adminMenuInput = input("\n Admin Menu\n\n" +
                                " - 1 Add User\n" +
                                " - 2 Remove User\n" +
                                " - 3 Logout\n\n - ")

        if adminMenuInput == "1":
            role = input("\n | Roles |\n\n Renter\n Maintenance\n Manager\n Admin\n\n Role: ").upper()

            try:
                uR = input(" Username: ").strip().upper()
                pW= getpass.getpass(" Password: ")
                fN = input(" First Name: ").upper()
                mN = input(" Middle Name: ").upper()
                lN = input(" Last Name: ").upper()
                pN = input(" Phone Number: ")
                lP = input(" Licence Plate Number: ")

                data = [[uR,pW,fN,mN,lN,pN,lP,0,0,0,role]]
                df = pd.DataFrame(data,columns = usersColumns)
                users = users.append(df, ignore_index=True)
                
                saveAll(users, apts)
                
            except:
                input("\n Error\n\n Back to Menu: ")

            return True
        
        elif adminMenuInput == "2":

            uR = input(" Username: ").strip().upper()

            confirm = input(" Confirm Deletion of - " + uR + " - (Y/N): ").upper()

            if confirm == 'Y':

                try:
                    
                    iD = users.loc[users['Username'] == uR].index[0]

                    users = users.drop(users.index[iD])
                    
                    saveAll(users, apts)
                    
                except:
                    input("\n Error\n\n Back to Menu: ")

            else:

                print("\n User Not Deleted")

                pass

            return True

        elif adminMenuInput == "3":

            try:
                confirm = input("\n Confirm Logout(Y/N): ").upper()
                if confirm == "Y":
                    return False
                else:
                    pass
                    
            except:
                input("\n Error\n\n Back to Menu: ")

            return True

        else:
            return True
                
                

    ##User Login
    login = userLogin(users)
    if login is False:
        print('Login Error')
        return True
    else:
        index = login[0]
        _User = login[1]
        perm = users.iloc[index][10]

        if perm == "RENTER":
            
            ##Renter Menu
            runRenter = True
            while runRenter is True:
                runRenter = renterMenu(users,apts,index,_User)
            if runRenter == False:
                return True

        elif perm == "MAINTENANCE":

            ##Maintenance Menu
            runMaintenance = True
            while runMaintenance is True:
                runMaintenance = maintenanceMenu(users,apts,index,_User)
            if runMaintenance == False:
                return True

        elif perm == "MANAGER":
            
            ##Manager Menu
            runManager = True
            while runManager is True:
                runManager = managerMenu(users,apts,index,_User)
            if runManager == False:
                return True

        elif perm == "ADMIN":

            ##Admin Menu
            runAdmin = True
            while runAdmin is True:
                runAdmin = adminMenu(users,index,_User)
            if runAdmin == False:
                return True
        
    
main()
