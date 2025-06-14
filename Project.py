# Project.py 
# This script implements a LSB steganography encryption project using AES for encryption and OpenCV for image manipulation.

import cv2
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import struct

# AES key derivation
def AES_key(key):
    return hashlib.sha256(key.encode()).digest()[:16] # AES requires a 16-byte key

# Encrypt the message
def encryption(data, key):
    cipher = AES.new(AES_key(key), AES.MODE_CBC)  # Create a new AES cipher in CBC mode
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))  # Encrypt the message with padding
    return cipher.iv + ciphertext  # Return the IV and ciphertext

# Decrypt the message
def decryption(cipher_data, key):
    iv = cipher_data[:16]  # Extract the IV from the first 16 bytes of the ciphertext
    ciphertext = cipher_data[16:]  # The rest is the actual ciphertext
    cipher = AES.new(AES_key(key), AES.MODE_CBC, iv)  # Create a new AES cipher with the extracted IV
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()  # Decrypt the ciphertext and remove padding

#Steganography Part
print("Welcome to the Project\nThis project implements LSB steganography with AES encryption to hide text in images.\n")
choice = input("Press 1 to hide text in an image\nPress 2 to extract text from an image\nEnter your choice: ")
if choice == '1':
    image_path = input("Enter the path of the image: ").strip('"')  # Input the image path
    # Read the image
    img = cv2.imread(image_path)
    if img is None:
        print("Error: Image not found.")
        exit()
    # Displaying how many characters can be hidden in the image
    max_chars = (img.shape[0] * img.shape[1] * img.shape[2]) // 8  # Calculate maximum characters that can be hidden
    print(f"Maximum characters that can be hidden in the image: {max_chars-4}")

    text = input("Enter the text to hide in the image: ")
    key = input("Enter the encryption key: ")   #Inputting the key
    if not text or not key:
        print("Error: Key and text cannot be empty.")
        exit()
    # Check if the text exceeds the maximum limit
    if len(text) > max_chars-4:  # 4 bytes are reserved for the length of the text
        print(f"Error: The text exceeds the maximum limit of {max_chars} characters.")
        exit()

    # Create dictionaries for character to ASCII and ASCII to character mapping
    d = {}
    c = {}
    for i in range(256):
        d[chr(i)] = i  # character to ASCII
        c[i] = chr(i)  # ASCII to character

    # Encrypt the message
    encrypted_data = encryption(text, key)
    l = len(encrypted_data)+4  # Length of the encrypted data plus 4 bytes for the length
    # Store the length of the encrypted data in the first 4 bytes
    encrypted_data = struct.pack('!I', l) + encrypted_data  # Pack the length as a 4-byte integer in big-endian format

    row, col, channel = 0, 0, 0  # Initialize pixel coordinates
    kl = 0  # Key length index

    for i in range(l):
        for bits in range(8):  # Process each bit of the encrypted data
            # Get the current pixel value
            curr_pixel = img[row, col, channel]
            bit= (encrypted_data[i] >> (7 - bits)) & 1
            # Modify the least significant bit of the pixel
            img[row,col,channel] = (curr_pixel & 0b11111110) | bit  # Clear the LSB and set it to the bit from the encrypted data
            # Move to the next pixel
            channel = (channel + 1) % 3  # Cycle through RGB channels
            if channel == 0:  # Move to the next pixel row if we reach the end of a channel
                col += 1    
                if col >= img.shape[1]:  # If we reach the end of the row, move to the next row
                    col = 0
                    row += 1
        kl = (kl + 1) % len(key)

    output_image_path = "encrypted_image.png"
    cv2.imwrite(output_image_path, img)  # Save the modified image
    os.startfile(output_image_path)  # Open the encrypted image
    print("Encryption successful. Encrypted image saved as", output_image_path)

elif choice == '2':
    image_path = input("Enter the path of the encrypted image: ").strip('"')  # Input the image path
    # Read the encrypted image
    img = cv2.imread(image_path)
    if img is None:
        print("Error: Image not found.")
        exit()
    key = input("Enter the decryption key: ")
    if not key:
        print("Error: Decryption key cannot be empty.")
        exit()
    decrypted_data = bytearray()
    row, col, channel = 0, 0, 0
    kl = 0
    #extract the length of the encrypted data from the first 4 bytes
    msg_length_bytes=bytearray()
    for i in range(4):
        byte=0
        for bits in range(8):
            # Get the current pixel value
            curr_pixel = img[row, col, channel]
            # Extract the least significant bit
            bit = curr_pixel & 1
            byte = (byte << 1) | bit  # Shift the byte and add the bit
            channel = (channel + 1) % 3
            if channel == 0:
                col += 1
                if col >= img.shape[1]:
                    col = 0
                    row += 1
        msg_length_bytes.append(byte)  # Append the byte to the length bytes
            
    # Now we know the length of the encrypted data
    msg_length = struct.unpack('!I', bytes(msg_length_bytes)) [0]

    for i in range(4, msg_length):  # Exclude the first 4 bytes which are the length
        byte = 0
        for bits in range(8):
            # Get the current pixel value
            curr_pixel = img[row, col, channel]
            # Extract the least significant bit
            bit = curr_pixel & 1
            byte = (byte << 1) | bit  # Shift the byte and add the bit
            # Move to the next pixel
            channel = (channel + 1) % 3
            if channel == 0:
                col += 1
                if col >= img.shape[1]:
                    col = 0
                    row += 1
        decrypted_data.append(byte)
    
    # Decrypt the message
    try:
        decrypted_text = decryption(decrypted_data, key)
    except Exception as e:
        print("Error: Decryption failed. Please check the key and try again.")
        exit()
    print("Decrypted text:", decrypted_text)
else:
    print("Invalid choice. Please enter 1 or 2.")
    exit()
