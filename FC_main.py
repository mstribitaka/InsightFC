import FC_recommender as rec

filename = "/Users/buxton/Desktop/DataScience/Insight/FastCompanyProject/logs/2015-06-08T00:00:00.000-3rnp5B4DSAZ7AnUAAAAA.log"
data1 = []
rec.convert_to_utf8(filename)
data1 = rec.parse_logfile(filename, data1) # Parse log data
df = rec.setup_df(data1) # put log data into a Pandas dataframe
df_subset = rec.get_subset(df,1000) # get a subset of data to work on
user_array = df_subset['IP'].unique()
image_array = df_subset['imagename'].unique()
(row, col, data) = rec.get_matrix_data(df_subset, user_array, image_array)
rec.matrix_to_sql(df_subset, user_array, image_array) # put data into a matrix, perform collaborative filtering, save results to SQL table
