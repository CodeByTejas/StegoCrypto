from django.shortcuts import render
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.http import JsonResponse
from cryptography.hazmat.primitives.asymmetric import dh
from Crypto.Cipher import AES, DES3
import hashlib, binascii
from PIL import Image
import numpy as np
from io import BytesIO

# Render the homepage
def index(request):
    return render(request, 'index.html')

# Encryption view
def encrypt(request):
    if request.method == 'POST':
        try:
            # 1. Extract input data
            user_key_size = int(request.POST.get('key_size', 1024))
            message = request.POST.get('message')
            image_file = request.FILES.get('image_file')

            # 2. Generate Diffie-Hellman parameters and shared key
            parameters = dh.generate_parameters(generator=2, key_size=user_key_size)
            private_key_A = parameters.generate_private_key()
            public_key_A = private_key_A.public_key()

            private_key_B = parameters.generate_private_key()
            public_key_B = private_key_B.public_key()

            # 3. Generate shared key
            shared_key_A = private_key_A.exchange(public_key_B)
            shared_key_B = private_key_B.exchange(public_key_A)
            shared_key = shared_key_A  # Both should be the same
            
            # Convert shared key to hexadecimal for easier display to the user
            shared_key_hex = shared_key.hex()

            # Log or display the shared key for testing purposes
            print(f"Shared Key (Hex): {shared_key_hex}")

            # Ensure message is in bytes before encryption
            message_bytes = message.encode('utf-8')

            # 4. AES Encryption
            aes_encrypted = aes_encrypt(message_bytes, shared_key)

            # 5. Triple DES encryption
            triple_des_encrypted = triple_des_encrypt(aes_encrypted, shared_key)

            # 6. Steganography: hide the encrypted message in the image
            encrypted_message_hex = binascii.hexlify(triple_des_encrypted).decode()
            encoded_image_path = encode_message_in_image(image_file, encrypted_message_hex)

            return JsonResponse({
                'message': 'Encryption successful',
                'image_path': encoded_image_path,
                'shared_key': shared_key_hex  # Include the shared key in the response
            })
        except Exception as e:
            return JsonResponse({'error': str(e)})

    return JsonResponse({'error': 'Invalid request'})

# Decryption view
def decrypt(request):
    if request.method == 'POST':
        try:
            decryption_key = request.POST.get('decryption_key')
            image_file = request.FILES.get('image_file')

            # Convert the decryption key from hex to bytes
            decryption_key_bytes = bytes.fromhex(decryption_key)

            # Extract the hidden message from the image
            extracted_message_hex = decode_message_from_image(image_file)

            # Decrypt the message using Triple DES and AES
            decrypted_message = decrypt_message(extracted_message_hex, decryption_key_bytes)

            return JsonResponse({'decrypted_message': decrypted_message})
        except Exception as e:
            return JsonResponse({'error': str(e)})

    return JsonResponse({'error': 'Invalid request'})

# Padding function
def pad(data):
    padding_size = 16 - len(data) % 16
    return data + bytes([padding_size] * padding_size)

# AES encryption
def aes_encrypt(message, key):
    key = hashlib.sha256(key).digest()  # AES expects a 256-bit key
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message))  # Message should be bytes

# Triple DES encryption
def triple_des_encrypt(message, key):
    key = hashlib.sha256(key).digest()[:24]  # Triple DES uses a 168-bit key (24 bytes)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(message))  # Message should be bytes

# AES decryption
def aes_decrypt(ciphertext, key):
    key = hashlib.sha256(key).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    padding_size = decrypted[-1]  # Get the padding size
    return decrypted[:-padding_size].decode('utf-8')  # Remove padding and decode to string

# Triple DES decryption
def triple_des_decrypt(ciphertext, key):
    key = hashlib.sha256(key).digest()[:24]
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    padding_size = decrypted[-1]  # Get the padding size
    return decrypted[:-padding_size]

# Decrypt message (using Triple DES and AES)
def decrypt_message(encrypted_message_hex, key):
    encrypted_bytes = binascii.unhexlify(encrypted_message_hex)
    decrypted_triple_des = triple_des_decrypt(encrypted_bytes, key)
    final_message = aes_decrypt(decrypted_triple_des, key)
    return final_message

# Encode message into an image using steganography
def encode_message_in_image(image_file, message):
    img = Image.open(image_file)
    img_array = np.array(img)

    message += "###"  # Add a delimiter to mark the end of the message
    message_bits = ''.join([format(ord(i), '08b') for i in message])  # Convert message to binary

    idx = 0
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            if idx < len(message_bits):
                # Modify the least significant bit of the red channel to hide the message
                img_array[i, j, 0] = int(format(img_array[i, j, 0], '08b')[:-1] + message_bits[idx], 2)
                idx += 1

    encoded_img = Image.fromarray(img_array)

    # Save image to in-memory file using BytesIO
    img_io = BytesIO()
    encoded_img.save(img_io, format='PNG')
    img_io.seek(0)

    # Use unique filename to avoid overwriting images
    image_name = 'encoded_image_' + hashlib.sha256(message.encode('utf-8')).hexdigest()[:10] + '.png'
    image_path = default_storage.save(image_name, ContentFile(img_io.getvalue()))

    return image_path

# Decode hidden message from an image using steganography
def decode_message_from_image(image_file):
    img = Image.open(image_file)
    img_array = np.array(img)

    message_bits = ""
    for i in range(img_array.shape[0]):
        for j in range(img_array.shape[1]):
            message_bits += format(img_array[i, j, 0], '08b')[-1]  # Extract least significant bit

    # Convert bits back to characters
    message = ''.join([chr(int(message_bits[i:i + 8], 2)) for i in range(0, len(message_bits), 8)])
    return message.split("###")[0]  # Remove the delimiter and return the message
