import sys 
import pytsk3
import hashlib
import sqlite3
import csv
import binascii
import re
import os
import datetime
# PyPDF2 isn't a part of the Python Standard Library, and will therefore need to be downloaded / installed: (pip3 install PyPDF2)
from PyPDF2 import PdfFileReader
import PIL.Image
from PIL.ExifTags import TAGS

############################################################
# Setting Up Database - Code Adapted From sqlitetutorial.net
############################################################

try:
    sqliteConnection = sqlite3.connect('Files_Database.db')
    sqlite_create_table_query = '''CREATE TABLE JPGS_PDFS (
                                id INTEGER PRIMARY KEY,
                                filename TEXT NOT NULL UNIQUE,
                                md5hash TEXT NOT NULL UNIQUE,
				metadata TEXT NOT NULL);'''

    cursor = sqliteConnection.cursor()
    print("Successfully Connected to SQLite")
    cursor.execute(sqlite_create_table_query)
    sqliteConnection.commit()
    print("SQLite Table Created")


except sqlite3.Error as error:
    print("Sqlite Table Already Exists", error)


# sys.argv[0] = The Python Script
# sys.argv[1] = The First File
# sys.argv[2] = The Second Filea

if len(sys.argv) < 2:
	print("Too Few Arguments, Exiting..")
	exit(1)

elif len(sys.argv) > 3:
	print("Too Many Arguments, Exiting..")
	exit(1)
	
file1 = sys.argv[1]
file2 = sys.argv[2]

# Creates a Python TSK / IMG_INFO Object. Img_Info Is Built Into Python TSK.
# This Allows Us To Be Able To Work With The Forensic Image.
image1 = pytsk3.Img_Info(file1)
image2 = pytsk3.Img_Info(file2)

# Grabs The Partition Table For The Image. We Give Volume_Info,(Another Built-In Library Function), The
# Object Being Held In The Variable image1 or image2.
# partitionTable = pytsk3.Volume_Info(image1)

# We Need An Object That Will Give Us Access To The File System.
# This Opens The File System & Stores It As An Object In filesystemObject.
# FS_Info Takes 2 Arguments: Our Image Object AND The Offset To Where Our File System Begins On The Partition We Want To Examine.
filesystemObject1 = pytsk3.FS_Info(image1)
filesystemObject2 = pytsk3.FS_Info(image2)

#######################################################################################
#######################################################################################
# The example below lets us access a specific file entry within a file system by path: 
# ---> fileobject = filesystemObject1.open("/$MFT")
# Note: A file entry can also be accessed based on its "inode":
# ---> file_entry = fs.open_meta(inode=15)
#######################################################################################

# fileobject = filesystemObject1.open("/$MFT")
# print ("File Inode:",fileobject.info.meta.addr)
# print ("File Name:",fileobject.info.name.name)

# Creation Time = (.crtime), Last Access = (.atime), Last MFT Change = (.ctime), Content Modification = (.mtime)
# Timestamp Will Be In Epoch Form. To Get It To A Human Readable Form, We Need To Use The datetime Library.
# print ("File Creation Time:", fileobject.info.meta.crtime)

# print ("File Creation Time:",datetime.datetime.fromtimestamp(fileobject.info.meta.crtime).strftime("%Y-%m-%d %H:%M:%S"))

# outfile = open(fileobject.info.name.name, "wb")
# read_random takes two parameters: the offset from the start of the file where we want to start reading and how many bytes of data we want to read.
# Reading in the contents of the $MFT from the beginning (0) to the end (fileobject.info.meta.size), which is the size of the file in bytes.
# filedata = fileobject.read_random(0,fileobject.info.meta.size)
# outfile.write(filedata)
#######################################################################################
#######################################################################################

# To look at all the files in the file system, instead of a file object, we use directory objects.
# Create a directory object by calling the function open_dir, and give it the path to the directory we want to open.
# Root Directory ---> (aka ‘/’ ) says to look at everything.

#directoryObject = filesystemObject1.open_dir(path="/")

#for eachObject in directoryObject:
	# Prints All Of The Files & Directories Located Within The Root Directory. What About SubDirectories?
	# If the entry is a directory then we need to check the contents of the sub directory as well.
#	print (eachObject.info.name.name)

#######################################################################################
#######################################################################################

# Create Directory To Hold Extracted Images

currentDirectory = os.path.dirname(os.path.realpath(__file__))
newDirectory = "Extractions"

try:
	os.mkdir(os.path.join(currentDirectory, newDirectory))

except:
	print ("Directory Already Exists, No Need To Create Again.")
#######################################################################################
#####################################################################################
# Recursion Code Adapted From learndfir.com - "Automating DFIR"

def directoryRecurse(directoryObject, parentPath):

	for eachObject in directoryObject:

# If there is no type, then they are unallocated or deleted.
# Not every directory entry is allocated. Unallocated  entries don't have an info.meta member OR the info.name.flags member has TSK_FS_NAME_FLAG_UNALLOC set.

		if eachObject.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_UNALLOC or eachObject.info.meta.type == None :
			#print ("DELETED File Name: ", eachObject.info.name.name)
			continue

# If our directory entry has . or .. as a file name we will skip it by using continue. (Continue skips the rest of the code and continues with the next iteration.)
# . and .. are special directory entries that allow us to be able to refer to the directory itself (.) and the parent directory (..). 
# If we were to keep calling the parent of itself, we could enter into an infinite loop of going back into the same directory. [& This happened to me.]

#The b specifies a bytes object.
		if eachObject.info.name.name == b"." or eachObject.info.name.name == b"..":
			print(". or .. Detected & Skipped!")
			continue

# If the contents of eachObject.info.meta.type are TSK_FS_META_TYPE_DIR then the directory entry is a directory.
# 0x02 is the value that represents a directory, but libtsk gives us a constant to use: TSK_FS_META_TYPE_DIR.
# If the directory entry is a directory, we need to recurse and find the files within the directory.

		if eachObject.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
			# The as_directory function which will return a directory object if the file object it is launched from is in fact a directory. The function will error out if not.
			sub_directory = eachObject.as_directory()
			#print (sub_directory)
			#print(eachObject.info.name.name)
			parentPath.append(eachObject.info.name.name)
			#print(parentPath)
			# Calls Itself
			directoryRecurse(sub_directory,parentPath)
			# Pop(-1_ means to remove the last element that was added to the list.
			parentPath.pop(-1)
			#print ("Directory: %s" % filepath)
			

# If the contents of eachObject.info.meta.type are TSK_FS_META_TYPE_REG then the directory entry is regular file.
# Libtsk also gives us a constant to use for regular files: TSK_FS_META_TYPE_REG.
# We are also making sure that our file isn't a 0 byte file.

		elif eachObject.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG and eachObject.info.meta.size != 0:
			  
			#searchJPG = re.match(b".*jpg",eachObject.info.name.name)
			#searchPDF = re.match(b".*pdf",eachObject.info.name.name)
			#if not searchJPG and not searchPDF:
			#	continue

			# read_random Takes 2 Parameters: 1) The offset from the start of the file where we want to start reading and 2) how many bytes of data we want to read.
			# Reading in the contents of the file from the beginning (0) to the end (fileobject.info.meta.size), which is the size of the file in bytes.
			filedata = eachObject.read_random(0,eachObject.info.meta.size)
			
			#####################################################################################
			# Looking At The Magic Numbers To Determine If It's A JPG or A PDF. If Not, Continue.
			#####################################################################################
			readme = str(binascii.hexlify(filedata)) [2:-1]
			searchJPG = re.match("ffd8ffe00010",readme)
			searchPDF = re.match("255044462d312e",readme)
			if not searchJPG and not searchPDF:
				continue

			#####################
			# Write Out To File
			#####################
			complete_filepath = os.path.join(currentDirectory, newDirectory, str(eachObject.info.name.name).replace("b'", "").replace("'",""))
			outputFile = open(complete_filepath, "wb")
			outputFile.write(filedata)
			outputFile.close()
			result = hashlib.md5(filedata)
			# Here, we will add the hash to the database, but for now, we'll just print.
			print ("File Name: ", str(eachObject.info.name.name).replace("b'", "").replace("'",""), "MD5 Hash:", result.hexdigest())
	
			#####################
			# Metadata Grabbing
			#####################

			if searchJPG:

			##################################################################################################################
			# Solution 1 - Sticks All Fields Into A Dictionary. Modified From CS-GY 6963 Lesson Materials From Week 7: exif.py
			##################################################################################################################
				#JPGFILE = PIL.Image.open(complete_filepath)
				#info = JPGFILE._getexif()
				#Creates An Empty Dictionary
				#metadata = {}
				#if info:
				#	for tag, value in info.items():
				#		decoded = TAGS.get(tag, tag)
				#		metadata[decoded] = value
				#else:
				#	print("No Metadata To Print!")

				#print(metadata)
			
			######################################################################################
			# Solution 2 - Can Grab Specific Fields - (Use If Making A Separate Table In Database)
			######################################################################################
				META_STRING = ""
				JPGFILE = PIL.Image.open(complete_filepath)
				exif = JPGFILE._getexif()

				# If A File Doesn't Have Any of These, It Will Return The Value "None" For That Field
				try:
					ResolutionUnit = get_exif_field(exif,'ResolutionUnit')
					Make = get_exif_field(exif,'Make')
					Model = get_exif_field(exif,'Model')
					Software = get_exif_field(exif,'Software')
					DateTime = get_exif_field(exif,'DateTime')
					Orientation = get_exif_field(exif,'Orientation')
					Artist = get_exif_field(exif,'Artist')
					ExifImageWidth = get_exif_field(exif,'ExifImageWidth')
					ExifImageHeight = get_exif_field(exif,'ExifImageHeight')
					XResolution = get_exif_field(exif,'XResolution')
					YResolution = get_exif_field(exif,'YResolution')
					ColorSpace = get_exif_field(exif,'ColorSpace')
					ExposureTime = get_exif_field(exif,'ExposureTime')
					Flash = get_exif_field(exif,'Flash')
					ShutterSpeedValue = get_exif_field(exif,'ShutterSpeedValue')
					ISOSpeedRatings = get_exif_field(exif,'ISOSpeedRatings')

					Happy = ("Resolution Unit:", ResolutionUnit
					       , " Make:", Make
					       , " Model:", Model
					       , " Software:", Software
				               , " Creation Time:", DateTime
					       , " Orientation:", Orientation
					       , " Artist:", Artist
					       , " Image Width (Pixels):", ExifImageWidth
					       , " Image Height (Pixels):", ExifImageHeight
					       , " X-Resolution:", XResolution
				               , " Y-Resolution:", YResolution
					       , " Color Space:", ColorSpace
					       , " Exposure Time:", ExposureTime
					       , " Flash:", Flash
					       , " Shutter Speed:", ShutterSpeedValue
					       , " ISO Speed:", ISOSpeedRatings)

					META_STRING = (str(Happy).replace(",","").replace("'","").replace("(","").replace(")",""))
	
				except:
					print("No Metadata")
			
			if searchPDF:
				META_STRING = ""
				try:
					PDFFILE = open(complete_filepath, 'rb')
					#strict = False Gets Rid Of Warning Messages
					pdf = PdfFileReader(PDFFILE, strict = False)
					docInfo = pdf.getDocumentInfo()
				
					num_of_pages = pdf.getNumPages()
					author = docInfo.author
					creator = docInfo.creator
					producer = docInfo.producer
					subject = docInfo.subject
					title = docInfo.title
					creationTime = datetime.datetime.fromtimestamp(eachObject.info.meta.crtime).strftime("%Y-%m-%d %H:%M:%S")
				
					Happy = ("Author:", author
					       , " Creator:", creator
					       , " Producer:", producer
					       , " Subject:", subject
				               , " Title:", title
					       , " Number of Pages:", num_of_pages
					       , " File Creation Time:", creationTime)

					META_STRING = (str(Happy).replace(",","").replace("'","").replace("(","").replace(")",""))
				except:
					print("PDF Damaged")

			#######################
			# Insert Into Database
			#######################
			try:		  
				  cursor.execute("INSERT INTO JPGS_PDFS (filename, md5hash, metadata) VALUES (?, ?, ?)", (str(eachObject.info.name.name).replace("b'", "").replace("'",""), result.hexdigest(), META_STRING))
				  sqliteConnection.commit()
				  print("Record Inserted Successfully Into JPGS_PDFS Table")
				  #cursor.close()

			except sqlite3.Error as error:
    				  print("Record Already Exists In Database JPGS_PDF...", error)


############################################################################################################
# Code Modified From Stackoverflow.com/questions/4764932/in-python-how-do-i-read-the-exif-data-for-an-image
############################################################################################################

def get_exif_field(exif,field):
	for (i,j) in exif.items():
		if TAGS.get(i) == field:
			return j

#############################################################

# To look at all the files in the file system, instead of a file object, we use directory objects.
# Create a directory object by calling the function open_dir, and give it the path to the directory we want to open.
# Root Directory ---> (aka ‘/’ ) says to look at everything.

# Need To Call That Twice, One For Each File.
# [] is an empty list. When the function calls itself for any directories it finds, it will use this list to keep track of the full path that led to it.

directoryObject1 = filesystemObject1.open_dir(path="/")
directoryRecurse(directoryObject1, [])

directoryObject2 = filesystemObject2.open_dir(path="/")
directoryRecurse(directoryObject2, [])

#######################################
#Need To Create The Report Now, .CSV
#######################################
# Python3 - You Can't Open A Text File As Binary ("w" VS "wb")

data = cursor.execute("SELECT * FROM JPGS_PDFS")

with open("myReport.csv", "w") as exportReport:
	writer = csv.writer(exportReport)
	writer.writerow(["File Count", "File Name", "MD5 Hash", "Metadata"])
	writer.writerows(data)
	print("Report Exported")

#######################################
# Close SQLite Connection
#######################################

if (sqliteConnection):
	cursor.close()
	sqliteConnection.close()
	print("The SQLite Connection Has Been Closed!")

