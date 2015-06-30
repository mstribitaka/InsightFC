# Import packages
import pandas as pd
import sys
import os
import shutil
import re
import glob
import numpy as np
from __future__ import division
from scipy import sparse
import pymysql as mdb
# packages for plotting
import matplotlib as mpl
import matplotlib.pyplot as plt
import seaborn as sns
%matplotlib inline



def parse_logfile(filename, db):
    """ Code written by Fast Company tech team to parse Apache Common Log data
        into array.
        Hacked by myself to run locally.
    """
    myFile = open(filename,'r')
    data = myFile.readlines()
    length = len(data)

    #parse line into separate parts and write into database
    #for i in range(length):
    for i in range(length):
        dataLine = data[i]
        
        #split first part with space eg. <134>2015-05-20T20:18:50Z
        colInfo1 = dataLine.split(" ",1)[0]
        #update dataLine exclude splitted part
        dataLine = dataLine.split(" ",1)[1]
    
        #split second part with space eg. cache-iad2148
        colInfo2 = dataLine.split(" ",1)[0]
        #update dataLine exclude splitted part
        dataLine = dataLine.split(" ",1)[1]
    
        #split third part with space and delete':' eg. fc-all[65147]
        colInfo3 = dataLine.split(" ",1)[0].replace(':','')
        #update dataLine exclude splitted part
        dataLine = dataLine.split(" ",1)[1]
    
        #split ip address part with space eg. fc-all[65147]
        colIp = dataLine.split(" ",1)[0]
        #update dataLine exclude splitted part
        dataLine = dataLine.split(" ",1)[1]
    
        #split remote logname part with space eg. "-"
        colLog = dataLine.split(" ",1)[0]
        #update dataLine exclude splitted part
        dataLine = dataLine.split(" ",1)[1]
        #print dataLine
    
        #split remote user part with space eg. "-"
        colUser = dataLine.split(" ",1)[0]
        #update dataLine exclude splitted part
        dataLine = dataLine.split(" ",1)[1]

        #split request received time part eg. "Wed, 20 May 2015 20:18:46 GMT"
        colTimeS = dataLine.split(" ",6)
#        colTime = str.join(' ',(colTimeS[0],colTimeS[1],colTimeS[2],colTimeS[3],colTimeS[4],colTimeS[5]))
        colTime = ' '.join(colTimeS[0:6])
        #update dataLine exclude splitted part
        dataLine = colTimeS[-1]
    
        #split request part eg. "GET /api/v1/posts?name=technology"
        colReqS = dataLine.split(" ",2)
        colReq = ' '.join(colReqS[0:2])
        #update dataLine exclude splitted part
        dataLine = colReqS[2]
    
        #split status part with space eg. "200"
        colStatus = dataLine.split(" ",1)[0]
        #update dataLine exclude splitted part
        dataLine = dataLine.split(" ",1)[1]
    
        #split host part with space eg. "www.fastcompany.com"
        colHost = dataLine.split(" ",1)[0]
        #update dataLine exclude splitted part
        if len(colHost) == len(dataLine):
            continue
        elif colHost is None or colHost == '(null)':
            colHost = 'NaN'
        else:
            dataLine = dataLine.split(" ",1)[1]
    
        # Not working, region is getting saved here instead (MMB)
        ##split Fastly SSL part with space eg. "(null)
        #colSSL = dataLine.split(" ",1)[0]
        #if len(colSSL) == len(dataLine):
        #    continue
        #elif colSSL is None or colSSL == '(null)':
        #    colSSL == 'NaN'
        #else:
        #    #update dataLine exclude splitted part
        #    dataLine = dataLine.split(" ",1)[1]
    
        #split X-Cache part, eg. "HIT or HIT, MISS"
        reCache = '(HIT, HIT ){1}|(MISS, MISS ){1}|(MISS, HIT ){1}|(HIT, MISS ){1}|(HIT ){1}|(MISS ){1}'
        colCacheS = re.search(reCache,dataLine)
        if colCacheS is None:
            colCache = 'NaN'
        else:
            colCache = colCacheS.group(0)
        #    #update dataLine exclude splitted part
            dataLine = re.sub(colCache,'',dataLine)
    
        # I can't see Referer in Logs - does it = Host??
        ##split referer part with space eg. "(http://m.fastcompany.com/3046429/the-new-rules-of-work/the-highest-paying-jobs-of-the-future-will-eat-your-life?utm_source=facebook)"
        #colRef = dataLine.split(" ",1)[0]
        #if len(colRef) == len(dataLine):
        #    continue
        #elif colRef is None or colRef == "(null)":
        #    colRef == 'NaN'
        #else:
        #    #update dataLine exclude splitted part
        #    dataLine = dataLine.split(" ",1)[1]
    
        #split region part with space eg. "(null)"
        colReg = dataLine.split(" ",1)[0]
        if len(colReg) == len(dataLine):
            continue
        elif colReg is None or colReg == "(null)":
            colReg == 'NaN'
        else:
            #update dataLine exclude splitted part
            dataLine = dataLine.split(" ",1)[1]
    
        #tricky thing here because there are three spaces after a city name, which actually makes it easier to identify a city.
        #split city part with space eg. "(null)"
        colCity = re.split("   ",dataLine)[0]
        if len(colCity) == len(dataLine):
            continue
        #elif colCity is None or colCity == "(null)":
            #colCity == 'None'
        else:
            #update dataLine exclude splitted part
            #dataLine1 = re.sub(colCity+'\s\s\s', '', dataLine)
            dataLine = dataLine[len(colCity)+3:]
    
    
        ##split last part of content length eg. "1234" and agent
        #reContentLen = '(?<=\s)([0-9]*$|(\(null\))$)'
        #colConLenS = re.search(reContentLen,dataLine)
        #if colConLenS is None:
        #    colConLen = 'NaN'
        #    colAgent = 'NaN'
        #else:
        #    colConLen = colConLenS.group(0)
        #    colAgent = dataLine[:-len(colConLen)-1]
            
        # Splitting up Content Length, Agent + Country - split Agent/Counry in DB
        #split last part of content length eg. "1234" and agent
        reContentLen = '(?<=\s)([0-9]*$|(\(null\))$)'
        colConLenS = re.search(reContentLen,dataLine)
        if colConLenS is None:
            colConLen = 'NaN'
            #colAgent = 'NaN'
        else:
            colConLen = colConLenS.group(0)
            colAgent = dataLine[:-len(colConLen)-1]
    
    
        db.append([colInfo1, colInfo2, colInfo3, colIp, colLog, colUser, colTime, colReq, colStatus, colHost,
			colCache, colReg, colCity, colAgent, colConLen])
    
    myFile.close()
    return db

def convert_to_utf8(filename):
    """ Code written by Fast Company tech team to convert input log data to utf8 format."""

	encodings = ('iso-8859-1', 'iso-8859-7')
	try:
		f= open(filename, 'r').read()
	except Exception:
		print "function 1"
		sys.exit(1)
	for enc in encodings:
		try:
			data = f.decode(enc)
			break
		except Exception:
			if enc == encodings[-1]:
				print "function 2"
				sys.exit(1)
			continue
	fpath = os.path.abspath(filename)
	newfilename = fpath + '.bak'
	shutil.copy(filename, newfilename)
	f = open(filename, 'w')
	try:
		f.write(data.encode('utf-8'))
	except Exception, e:
		print e
	finally:
		f.close()

# setup pandas dataframe 
def setup_df(data):
    """ Parse log data into Pandas data frame. """

    cols = ['Info1','Info2','Info3','IP','Log','User','Time','Request','Status','Host','Cache', 'Region','City','Agent',
        'Length']
    df = pd.DataFrame(data, columns=cols)
    # Extract domain name from Host entry
    df['domain'] = df['Host'].str.split('//|/') # split client request into components
    df['host2'] = df['domain'].astype(list) # convert from pandas object to list for easy manipulation
    df['domain'] = [h[1] if len(h) > 1 else h for h in df['domain']] # extract domain name

    # Extract image filename from Request entry
    df['imagename'] = df['Request'].str.split('GET')
    df['imagename'] = df['imagename'].astype(list)
    df['imagename'] = [h[-1] for h in df['imagename']]
    # Only focus on jpgs, gifs and mp4s
    df['nonFC_image'] = df['imagename'].str.contains('.jpg|.gif|.mp4')
    df['image_type'] = [h[1] if len(h) > 1 else h for h in df['imagename'].str.split('.')]
    df['image_type'] = df['image_type'].astype(str)
    return df

def get_subset(df, num_lines):
    '''Get subset of dataframe for matrix work'''
    num_subset = num_lines # number of lines taken from df with non-Fast Company images
    df_nonFCimage = df[df['nonFC_image']]
    df_subset = df.loc[np.random.choice(df_nonFCimage.index, num_subset, replace=False)]
    return df_subset

def get_matrix_data(df_subset, user_array, image_array):
    """ Prepare data for matrix setup. """

    grouped_user = df_subset['imagename'].groupby(df_subset['IP']) # group of images for each user
    row = []
    col = []
    data = []
    for i in range(len(user_array)):
        user_ip = user_array[i]
    #   grouped_user_image_array = ARRAY OF IMAGES FROM GROUPED_USER 
        grouped_user_image_array = np.array(grouped_user.get_group(user_ip).unique()) # which images did user see?
        grouped_user_image_count = np.array(grouped_user.get_group(user_ip).value_counts()) #how many times did user see each image?
        #if len(grouped_user_image_array) > 1: # user needs to have seen more than one image
        for j in range(len(image_array)):
            if image_array[j] in grouped_user_image_array:
                image_count_index = np.where(grouped_user_image_array==image_array[j])
                data.append(grouped_user_image_count[image_count_index][0])
            else:
                data.append(0)
            col.append(j)
        row.append(i)
    return (row, col, data)

def get_sim_matrix(row, col, data):
    """ Create similarity matrix from image-based matrix. """

    A = sparse.coo_matrix((data,(row,col)))
    T = A.transpose().dot(A)
    Darray = np.sqrt(1./T.diagonal())
    X = sparse.dia_matrix((Darray,0),shape=(len(Darray),len(Darray)))
    S = X.dot(T.dot(X)) # This is my similarity matrix
    return (A, S)

def get_seen_unseen_images(A, S, row, user_array, image_array):
    """ Get array of unseen images for every user.
    Loop over every user_id, build 2, 2D arrays that gives:
    1. images each user has seen; and 
    2. images each user is recommended to see
    These arrays will be saved to sql databases that will be uploaded to the web server
    and from which the web app will query. """

    # row array entries are indices to users in user_array
    image_seen_array = []
    image_unseen_array = []   
    unique_row = set(row) # get unique row numbers
    for rownum in unique_row:
        user_id = user_array[rownum] # This is an IP address
        R = A.getrow(rownum) # get user vector 
        scores = S.dot(R.transpose()) # dot product similarity matrix with user vector
        scores_array = np.squeeze(scores.toarray())
        sorted_image_indices = np.argsort(scores_array) # OKAY HERE??
        image_seen = R != 0
        image_seen_indices = np.where(image_seen.toarray())[1]
        image_seen_indices = image_seen_indices.tolist()
        unseen_image_indices = [x for x in sorted_image_indices if x not in image_seen_indices]
        unseen_image_indices = unseen_image_indices[:10]  # indices of sorted images in descending order
        for i in image_seen_indices:
            image_seen_array.append([user_id, image_array[i]])
        for i in unseen_image_indices:
            image_unseen_array.append([user_id, image_array[i]])
    return (image_seen_array, image_unseen_array)
    
def create_SQL(A, S, row, user_array, image_array):
    """ Save seen and unseen image arrays for every user into MySQL databases. """

    (image_seen_array, image_unseen_array) = get_seen_unseen_images(A, S, row, user_array, image_array)
    # Save image_seen and image_unseen arrays to sql database
    con = mdb.connect('localhost', 'root', '', 'fastdb') #host, user, password, #database
    with con:
        cur = con.cursor()
        cur.execute("DROP TABLE IF EXISTS SeenImages")
        cur.execute("CREATE TABLE SeenImages(Id INT PRIMARY KEY AUTO_INCREMENT,User VARCHAR(25), Imagename VARCHAR(250))")
    
        cur.execute("DROP TABLE IF EXISTS UnseenImages")
        cur.execute("CREATE TABLE UnseenImages(Id INT PRIMARY KEY AUTO_INCREMENT,User VARCHAR(25), Imagename VARCHAR(250))")
    
    #for user,imagename in image_seen_array:
        for user, imagename in image_seen_array:
            cur.execute("INSERT INTO SeenImages(User, Imagename) VALUES (%s,%s)", (user, imagename))
                
            for user, imagename in image_unseen_array:
                cur.execute("INSERT INTO UnseenImages(User, Imagename) VALUES (%s,%s)", (user, imagename))

    con.close()
    return
                
    
def matrix_to_sql(df_subset, user_array, image_array):
    '''Setup initial sparse matrix
        FUTURE: see if I can use scikit_learn to construct 'dense' matrix then
        find row/col indices where data != zero
        convert to sparse matrix'''

    (A, S) = get_sim_matrix(row, col, data) # A is sparse matrix, S is similarity matrix
    create_SQL(A, S, row, user_array, image_array)
    return 
