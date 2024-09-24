# StegoCrypt: A Django-Based Hybrid Encryption and Steganography System

StegoCrypt is a hybrid encryption system built using the Django web framework. It allows users to securely encrypt messages using a combination of AES (Advanced Encryption Standard) and Triple DES encryption algorithms and hide the encrypted messages within images using steganography. This ensures not only the confidentiality of the message but also that its presence remains hidden. 

 ## Key Features:

- Hybrid Encryption (AES + Triple DES): Combines the strength of two encryption algorithms—AES for message encryption and Triple DES for an additional layer of security.
  
- Diffie-Hellman Key Exchange: Utilizes the Diffie-Hellman key exchange mechanism to securely generate a shared encryption key between two users without transmitting the key itself.
  
- Steganography: The encrypted message is hidden within the least significant bits of the image pixels, making the message imperceptible to the human eye.

- Decryption with Shared Key: To decrypt the message, the user must provide the shared key (generated during encryption) in order to successfully extract and decrypt the message from the image.

- Image Embedding: Supports embedding encrypted messages within images in such a way that the image can be saved and shared without arousing suspicion.
  
- Secure Data Exchange: This project is ideal for secure communication where the presence of the message itself should remain hidden.

 ## How It Works:

1. Message Encryption:
   - A user inputs a message and uploads an image.
   - The system generates a shared key using Diffie-Hellman key exchange.
   - The message is encrypted using AES and Triple DES.
   - The encrypted message is embedded into the uploaded image using steganography.
   - The system provides a downloadable image with the hidden encrypted message and returns the shared key in hexadecimal format.

2. Message Decryption:
   - The user uploads the image containing the hidden encrypted message and provides the shared key (generated during encryption).
   - The system extracts the hidden message from the image.
   - The message is decrypted using the shared key, AES, and Triple DES.

 ## Technologies Used:

- Python: Core language for cryptographic operations.
- Django: Web framework to handle the backend logic and serve the web interface.
- Cryptography: For Diffie-Hellman key exchange and AES/Triple DES encryption/decryption.
- Pillow: Python Imaging Library (PIL) for image processing and steganography.
- NumPy: Used to manipulate image data for steganography operations.
- HTML/CSS: Basic front-end interface for interacting with the encryption and decryption process.
  
 ## Installation Instructions:

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/StegoCrypt.git
   cd StegoCrypt
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up Django:
   ```bash
   python manage.py migrate
   python manage.py runserver
   ```

4. Open your browser and go to `http://127.0.0.1:8000/`.

 Usage:

1. Encrypting a Message:
   - Navigate to the encryption page.
   - Enter the message you wish to encrypt.
   - Upload an image to hide the encrypted message.
   - The encrypted image and the shared key (in hex format) will be displayed and available for download.

2. Decrypting a Message:
   - Navigate to the decryption page.
   - Upload the image containing the hidden encrypted message.
   - Provide the shared key generated during encryption.
   - The system will display the decrypted message if the correct key is provided.

 ## Project Structure:

```
StegoCrypt/
│
├── encryption_app/
│   ├── templates/
│   │   └── index.html  # Frontend form for encryption/decryption
│   ├── views.py  # Contains the main logic for encryption, decryption, and steganography
│   ├── urls.py  # URL routing for the app
│
├── hybrid_encryption/
│   ├── settings.py  # Django project settings
│   ├── urls.py  # Main URL routing for the project
│
├── manage.py  # Django management script
├── README.md  # Project description
├── requirements.txt  # Python dependencies
```

 ## Future Enhancements:

- Improved Steganography: Add support for different steganography techniques, including embedding data in multiple color channels or even in audio or video files.
  
- Public Key Encryption (RSA): Introduce RSA for encrypting the AES and Triple DES keys before they are shared over insecure channels.
  
- Multi-factor Authentication: Add multi-factor authentication (e.g., using OTP or biometric) to enhance user security.
  
- More Encryption Algorithms: Add support for more encryption algorithms like ChaCha20 or Blowfish.

 Contributing:

Feel free to fork this repository, create a branch, and make contributions. Pull requests are welcome!

 License:

This project is licensed under the MIT License. See the LICENSE file for details.


