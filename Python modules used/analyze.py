import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.widgets import Slider

def process_df(df, flag, m, N):
    arr = np.empty(5*m+5)
    print(df.head(10))
    print(df.shape[0])
    arr.fill(0)

    f = 0
    freq_dict = {}
    for key in df['Address']:
        if (key//N) in freq_dict:
            freq_dict[key//N] += 1
            if freq_dict[key//N] > m and f == 0:
                print("oops! ", key)
                f = 1
        else:
            freq_dict[key//N] = 1

    for key in freq_dict:
        arr[freq_dict[key]] += 1

    plt.bar(np.arange(len(arr)), arr)
    plt.xlabel('Number of faults in bucket of ' + str(m))
    plt.ylabel('Frequency')
    if flag == 0:
        plt.title('Anonoymous Write Faults')
    else:
        plt.title('Anonoymous Read Faults')
        
    # Display the y-axis value of each bar in the histogram
    for rect in plt.gca().patches:
        height = rect.get_height()
        plt.gca().annotate(f'{height:.0f}', (rect.get_x() + rect.get_width() / 2, height),
                           ha='center', va='bottom')
    plt.legend([f'Fault Count: {df.shape[0]-1}'])

    if flag ==0:
        plt.savefig('testcases/testcase8/anon_write_16.png')    
    else:
        plt.savefig('testcases/testcase8/anon_read_16.png')
    plt.close()

def stride_df(dframe, flag):

    df = dframe.copy()

    df.loc[abs(df['Address_Diff']) > 32, 'Address_Diff'] = 0
    # print(df.head(30))


    #############
    # Setting Plot and Axis variables as subplots()
    # function returns tuple(fig, ax)
    Plot, Axis = plt.subplots()

    # Adjust the bottom size according to the
    # requirement of the user
    plt.subplots_adjust(bottom=0.25)

    x = np.arange(0, df.shape[0] )
    l = plt.plot(x, df['Address_Diff'], marker='o', linestyle= None)

    # Choose the Slider color
    slider_color = 'Green'
    plt.grid(True)

    # Set the axis and slider position in the plot
    axis_position = plt.axes([0.2, 0.1, 0.65, 0.03],
                            facecolor = slider_color)
    slider_position = Slider(axis_position,
						'Pos', 0.1, 9000.0)

    def update(val):
        pos = slider_position.val
        Axis.axis([pos, pos+20, -32, 32])
        Plot.canvas.draw_idle()

    # update function called using on_changed() function
    slider_position.on_changed(update)
    # Display the plot
    plt.show()
    #############
    
    # Plot the difference of consecutive row addresses

    ## uncomment from here

    # x = np.arange(0, df.shape[0] )
    # plt.figure(figsize=(10, 6))
    # plt.scatter(x, df['Address_Diff'])
    # # plt.plot(df['Address_Diff'], marker='o', linestyle='-')
    # plt.title('Stride Pattern of Memory Access (overall)')
    # plt.xlabel('Index')
    # plt.ylabel('Difference of Consecutive Addresses')
    # plt.grid(True)
    # if flag ==0:
    #     plt.savefig('testcases/testcase8/stride_write_2.png')
    # else:
    #     print('Size of stridde read ', df.shape[0])
    #     plt.savefig('testcases/testcase8/stride_read_2.png')

    # plt.close()

    ## uncomment till here

def process_csv(filename):
    # Read the CSV file into a DataFrame
    df = pd.read_csv(filename, names=['Address', 'Flag', 'Time', 'PID'])
    # print(df.shape[0])
    print(df.shape[0])
    # Filter rows based on flag values 1 or 2
    df = df[df['Flag'].isin([0, 1])]
    # Filter rows based on flag values 1 or 2 and exclude 3 or 4
    df = df[df['Flag'].isin([0, 1]) & ~df['Flag'].isin([2, 3])]
    # Convert hexadecimal addresses to integers
    df['Address'] = df['Address'].apply(lambda x: int(x, 16))

    # Define parameters
    m = 16
    N = 4*1024*16

    df0 = df[df['Flag'] == 0].copy()
    df1 = df[df['Flag'] == 1].copy()
    
    df0['Address_Diff'] = df0['Address'].diff()
    df0['Address_Diff'] = df0['Address_Diff']//4096


    
# # Iterate over the index of the DataFrame

    df1['Address_Diff'] = df1['Address'].diff()
    df1['Address_Diff'] = df1['Address_Diff']//4096
    
    # process_df(df0, 0, m, N)
    # process_df(df1, 1, m, N)

    # stride_df(df1, 1)
    stride_df(df0, 0)
    

if __name__ == '__main__':
    process_csv("./testcases/testcase7/logfile.txt")