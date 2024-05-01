
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

def extract_levels(address):
    # Convert the address to binary
    binary_address = bin(int(address, 16))[2:].zfill(48)  # Assuming 48-bit address

    # Extract pte, pmd, pud, and pgd levels from the binary address
    offset = int(binary_address[-12:], 2)
    pte = int(binary_address[-21:-12], 2)
    pmd = int(binary_address[-30:-21], 2)
    pud = int(binary_address[-39:-30], 2)
    pgd = int(binary_address[-48:-39], 2)

    return offset, pte, pmd, pud, pgd

# Read the CSV file
df = pd.read_csv('log3.txt', header=None, names=['address', 'type','time']) #keep in mind the path.

# Initialize an empty image array
image = np.zeros((512, 512, 3), dtype=np.uint8)*255

# Initialize a set to store unique pgd values
unique_pgd = set()
# Process each row in the dataframe
curr_frame = df['time'][0]//10000000
for index, row in df.iterrows():
    if (row['time']//10000000 > curr_frame):
        # Save the image as a PNG file
        plt.imsave('./address_faults/address_faults_script'+str(curr_frame)+'.png', image) #keep in the mind the path.
        curr_frame = row['time']//10000000
        # Initialize an empty image array
        image = np.zeros((512, 512, 3), dtype=np.uint8)*255
    # Extract the address and type from the row
    address = row['address']
    address_type = 1 + int(row['type'])

    # Extract offset, pte, pmd, pud, and pgd levels
    offset, pte, pmd, pud, pgd = extract_levels(address)

    # Check if pgd-pud pair is not already used in the image
    if image[pmd, pte, 0] == 0 and image[pmd, pte, 1] == 0 and image[pmd, pte, 2] == 0:
        if address_type == 1:
            image[pmd, pte] = [255, 0, 0]  # Red
        elif address_type == 2:
            image[pmd, pte] = [0, 255, 0]  # Green
        elif address_type == 3:
            image[pmd, pte] = [0, 0, 255]  # Blue
        elif address_type == 4:
            image[pmd, pte] = [255, 255, 0]  # Yellow
    unique_pgd.add((pgd, pud))

# Save the image as a PNG file
plt.imsave('address_faults_script.png', image)

# # Save unique pgd values and corresponding pud levels to a file
# with open('unique_pgd_script.txt', 'w') as f:
#     f.write("Unique PGD values and corresponding PUD levels:\n")
#     for pgd, pud in unique_pgd:
#         f.write(f"PGD: {pgd}, PUD: {pud}\n")
