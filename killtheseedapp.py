import hashlib
import hmac
import binascii
from PIL import Image
from pbkdf2 import PBKDF2
import requests
import tkinter as tk
import pyperclip
from time import sleep

from tkinter import filedialog, simpledialog

# Function to select an image file
def select_image():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    filename = filedialog.askopenfilename(title="Select an Image", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
    root.destroy()  # Destroy the root window
    return filename

# Function to ask for a password
def ask_password():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    password = simpledialog.askstring("Password", "Enter a password to protect private key!:", show='*')
    root.destroy()  # Destroy the root window
    return password

# Function to load and preprocess the image
def load_image(image_path):
    image = Image.open(image_path)
    image = image.resize((1024, 1024))  # Resize to standard dimensions
    return image

# Function to save the resized image
def save_resized_image(image, save_path):
    image.save(save_path)



# Function to download and save the BIP-39 wordlist to a file
def download_wordlist(url='https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt', filename='bip39_wordlist.txt'):
    response = requests.get(url)
    response.raise_for_status()  # Ensure we notice bad responses
    with open(filename, 'w') as file:
        file.write(response.text)

# Function to load the BIP-39 wordlist from a file
def load_wordlist(filename='bip39_wordlist.txt'):
    with open(filename, 'r') as file:
        wordlist = [line.strip() for line in file.readlines()]
    return wordlist

# Function to download and save the BIP-39 wordlist to a file
def download_wordlist(url='https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt', filename='bip39_wordlist.txt'):
    response = requests.get(url)
    response.raise_for_status()  # Ensure we notice bad responses
    with open(filename, 'w') as file:
        file.write(response.text)

# Function to load the BIP-39 wordlist from a file
def load_wordlist(filename='bip39_wordlist.txt'):
    with open(filename, 'r') as file:
        wordlist = [line.strip() for line in file.readlines()]
    return wordlist

# Function to generate SHA-256 hash of the image
def image_hash(image):
    image_data = image.tobytes()
    hash_object = hashlib.sha256(image_data)
    return hash_object.hexdigest()

# Function to generate 128 unique 128-bit segments
def generate_segments(image_hash):
    segments = []
    for i in range(128):
        hash_input = image_hash + str(i)
        hash_output = hashlib.sha256(hash_input.encode()).hexdigest()
        segment = hash_output[:256]  # First 128 bits (32 hex characters)
        segments.append(segment)
    return segments

# Function to calculate pixel coordinates from 128-bit segment
def segment_to_coordinates(segment):
    x = int(segment[:16], 16) % 1024
    y = int(segment[16:], 16) % 1024
    return (x, y)

# Function to extract RGB values from selected pixels
def extract_rgb_values(image, coordinates):
    pixel_data = []
    for coord in coordinates:
        pixel = image.getpixel(coord)
        pixel_data.append(pixel)
    return pixel_data

# Function to concatenate RGB values into binary string
def concatenate_pixel_data(pixel_data):
    binary_string = ''
    for pixel in pixel_data:
        binary_string += '{:08b}{:08b}{:08b}'.format(pixel[0], pixel[1], pixel[2])
    return binary_string

# Function to hash the concatenated pixel data
def hash_pixel_data(binary_string):
    pixel_data_hash = hashlib.sha256(binary_string.encode()).digest()
    binary_hash = ''.join(format(byte, '08b') for byte in pixel_data_hash)
    return binary_hash

# Updated function to convert binary string to mnemonic seed phrase
def binary_to_mnemonic(binary_string, wordlist):
    # Use only the first 256 bits (32 bytes) for practical purposes
    binary_segment = binary_string[:1024]
    
    # Convert binary_segment to hexadecimal and calculate the SHA-256 hash
    hex_segment = hex(int(binary_segment, 2))[2:].zfill(64)
    checksum = hashlib.sha256(binascii.unhexlify(hex_segment)).hexdigest()[:1]  # First 4 bits of the hash
    
    # Convert the checksum to binary and append it to the binary segment
    checksum_binary = bin(int(checksum, 16))[2:].zfill(4)
    entropy_with_checksum = binary_segment + checksum_binary
    
    # Convert the entropy_with_checksum to words
    words = []
    for i in range(0, len(entropy_with_checksum), 11):
        index = int(entropy_with_checksum[i:i+11], 2)
        words.append(wordlist[index])
    return ' '.join(words)

# Function to derive keys from mnemonic seed
def mnemonic_to_seed(mnemonic, passphrase=''):
    salt = passphrase + 'mnemonic' 
    seed = PBKDF2(mnemonic, salt, iterations=2048, macmodule=hmac, digestmodule=hashlib.sha512).read(256)
    return seed

# Function to derive private and public keys using ECDSA
def derive_keys(seed):
    private_key = hashlib.sha256(seed[:256]).hexdigest()
    # Public key derivation would normally involve elliptic curve multiplication,
    # for simplicity, we demonstrate it here with a hash
    public_key = hashlib.sha256(private_key.encode()).hexdigest()
    return private_key, public_key


# Example usage
if __name__ == "__main__":
    # Ensure the wordlist is downloaded
    download_wordlist()
    
    # Load the wordlist from the file
    wordlist = load_wordlist()
    
    # Let the user select an image
    image_path = select_image()
    if not image_path:
        print("No image selected. Exiting...")
        exit()

    image = load_image(image_path)

    # Ask the user for a password
    password = ask_password()
    if not password:
        print("No password entered")

    # Save the resized image
    resized_image_path = "resized_image.png"  # You can choose a different path or filename
    save_resized_image(image, resized_image_path)
    print(f"Resized image saved as {resized_image_path}")
    
    img_hash = image_hash(image)
    segments = generate_segments(img_hash)
    coordinates = [segment_to_coordinates(segment) for segment in segments]
    pixel_data = extract_rgb_values(image, coordinates)
    binary_string = concatenate_pixel_data(pixel_data)
    pixel_data_hash = hash_pixel_data(binary_string)
    mnemonic_seed = binary_to_mnemonic(pixel_data_hash, wordlist)

    
    seed = mnemonic_to_seed(mnemonic_seed)
    private_key, public_key = derive_keys(seed)
    
    pyperclip.copy(private_key)
    print("Private Key copied to clipboard!")
    print("Image:", image_path)
    print("Mnemonic Seed Phrase:", mnemonic_seed)
    print("Private Key:", private_key)
    print("Public Key:", public_key)
    print("This window will close in 20 seconds!")
    sleep(20)