
import struct
import sys
import csv
# Path to the log file
log_file_path = sys.argv[1]

# Path to the CSV file
csv_file_path = sys.argv[2]

# Open the log file for reading in binary mode
with open(log_file_path, 'rb') as log_file:
    # Open the CSV file for writing
    with open(csv_file_path, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['Fault Address', 'Fault Type','Time']) #comment out to actually run other image generating script.

        # Read the log file byte by byte
        while True:
            # Read 5 bytes from the file
            entry_bytes = log_file.read(5)
            time_bytes = log_file.read(8)
            if not entry_bytes:
                break  # End of file

            # Unpack the 5-byte entry into address and fault type
            packed_data = int.from_bytes(entry_bytes, byteorder='big')
            address = hex((packed_data >> 4) << 12)
            fault_type = packed_data & 0x3
            time = int.from_bytes(time_bytes, byteorder='big')
            # Write the address and fault type to the CSV file
            csv_writer.writerow([address, fault_type,time])
