﻿# 🔐 Steganography with AES Encryption using Python & OpenCV

This project demonstrates a secure method for hiding sensitive textual data within an image using **LSB (Least Significant Bit) steganography**, along with **AES (Advanced Encryption Standard)** encryption. By combining these two techniques, the system ensures both **confidentiality** and **covertness** of the data.

The script is developed using **Python**, and it leverages **OpenCV** for image processing and **PyCryptodome** for AES encryption. This project is suitable for educational purposes, cybersecurity demonstrations, and introductory steganography applications.

---

## 📂 Included Files

- `Project.py` – Main Python script that performs AES encryption and LSB steganography.
- `Original_image.png` – Sample image used as the input (cover image).
- `Encrypted_image.png` – Output image with hidden encrypted data embedded using LSB.

> 🔎 *Note: These images are not displayed here but are included in the repository for reference and testing.*

---

## 🔧 Features

- Hides encrypted text data securely within an image using LSB technique.
- Utilizes **AES encryption in CBC mode** for strong cryptographic protection.
- Can extract and decrypt hidden messages with the correct secret key.
- Displays the maximum text capacity supported by the image.
- Supports both **encryption + embedding** and **extraction + decryption** modes via terminal.

---

## 🚀 How It Works

### 🧪 Hiding Text in an Image:
1. The user provides:
   - The path to the original image (`Original_image.png`)
   - The secret text message
   - An encryption key
2. The message is encrypted using AES.
3. The encrypted binary data is embedded into the **least significant bits** of the image pixels.
4. The modified image is saved as `Encrypted_image.png`.

### 🔓 Extracting Hidden Text:
1. The user inputs:
   - The path to the encrypted image (`Encrypted_image.png`)
   - The decryption key
2. The script reads the embedded data from the LSBs of the image.
3. AES decryption is performed to reveal the original message.

---

## 🛠️ Technologies Used

- Python 3
- OpenCV (`cv2`)
- PyCryptodome (`Crypto`)
- `struct` and `hashlib` (for binary data handling and key hashing)

---

## 💻 How to Run

1. **Install dependencies**:

```bash pip install opencv-python pycryptodome```

2. **Run the Script**:

```bash python Project.py```

3. **Choose an operation**:

Press 1 → Encrypt text and hide it in an image.

Press 2 → Extract and decrypt hidden text from an image.

**📌 Use Cases**
Secure message transmission via images

Covert data exchange in cybersecurity research

Educational demonstration of steganography and cryptography

Watermarking and hidden metadata embedding

**👤 Author**
Aditya Raj
 | Cybersecurity Intern | Edunet Foundation

**⚠️ Disclaimer**
This project is for educational purposes only. Avoid using it to hide or transmit sensitive or illegal data. Use responsibly.


