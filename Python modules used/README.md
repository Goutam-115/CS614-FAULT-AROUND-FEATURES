The analyze.py python module is to analyze the patterns and statistics for different type of page faults, mainly anonymous read, write using the csv file that we generated as logfiles in each of the testcases during our analysis.Before running this python module please ensure to provide correct path addresses to save the plots.

The image_generation python module takes the logfiles csv as an argument and creates various snapshots of the address space at small time intervals with each page represented by a pixel and all different page faults occuring in that time frame are represented by different colours. Before running this python module please ensure to provide correct path addresses to save the images.