import os

"""
Text-based file copy program
----------------------------
This program copies the contents of one text file to another. 
It is structurally identical to the binary block-based version, 
but operates on character streams instead of raw bytes.
"""

# Source and destination filenames
fname = 'infile.txt'
fname2 = 'outfile.txt'

# Resolve absolute paths for clarity in output
path = os.path.abspath(fname)
path2 = os.path.abspath(fname2)

# Notify user of the copy operation
print('Copying', path, 'to', path2)

# Set the block size (characters instead of bytes)
blocksize = 16
# Total character counter
totalsize = 0

# ----------------------------------------------------------------------
# Differences from binary version:
# 1. Files are opened in text mode ('r' and 'w') with UTF-8 encoding,
#    not in binary mode ('rb', 'wb').
# 2. A string buffer is used instead of a bytearray.
# 3. Data is read in fixed-size character blocks using read(blocksize).
# 4. totalsize counts characters rather than bytes.
# ----------------------------------------------------------------------

# Open the files in text mode
file = open(fname, 'r', encoding='utf-8')
file2 = open(fname2, 'w', encoding='utf-8')

# Loop until the end of file
while True:
    # Read up to blocksize characters from source file
    data = file.read(blocksize)
    num = len(data)              # number of characters actually read
    totalsize += num             # update totalsize counter

    # Print the data block (as text)
    print(num, data)

    # Check for end of file
    if num == blocksize:
        # Full block read: write directly
        file2.write(data)
    else:
        # Partial block (last segment): write and exit loop
        file2.write(data)
        break

# Close files to flush buffers and release resources
file.close()
file2.close()

# Report total characters copied
print('Read', totalsize, 'characters')
