# File-Cryptor

File Cryptor is a Python application built using Tkinter for GUI and cryptography library for file encryption and decryption.


![home-screen](https://github.com/deepribadia2003/File-Cryptor/blob/main/sample_images/img1.png)
## Features

- **Encryption:** Encrypts files using AES encryption with CBC mode and PKCS7 padding.
- **Decryption:** Decrypts AES encrypted files, ensuring data integrity with signature verification.
- **Password Protection:** Supports password input with length validation.
- **Console Output:** Displays status messages and errors during encryption and decryption operations.
- **File Handling:** Handles file selection, deletion of original files after encryption/decryption.

## Technologies Used

- **Python:** Version 3.6 and above
- **Tkinter:** Python's standard GUI (Graphical User Interface) toolkit
- **cryptography:** Python library for secure communications
- **OS module:** Provides functions for interacting with the operating system
- **Struct module:** Provides tools for parsing and formatting structured binary data

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/deepribadia2003/File-Cryptor.git

2. Install dependencies:
   ```bash
   pip install cryptography

3. Run the application:
   ```bash
   python file_cryptor.py

 ## Usage

1. **Select a File:**
   - Click on the "Select File" button to choose the file you want to encrypt or decrypt.

![select-a-file](https://github.com/deepribadia2003/File-Cryptor/blob/main/sample_images/img2.png)

2. **Enter Password:**
   - Enter a password (up to 20 characters) in the password field. The application enforces a maximum password length of 20 characters.

![enter-password](https://github.com/deepribadia2003/File-Cryptor/blob/main/sample_images/img3.png)

3. **Encrypt or Decrypt:**
   - After selecting a file and entering the password, click the "Encrypt" button to encrypt the selected file.
   - Click the "Decrypt" button to decrypt a previously encrypted file.

![encryption](https://github.com/deepribadia2003/File-Cryptor/blob/main/sample_images/img4.png)

4. **Console Output:**
   - The application's console output displays status messages and errors during the encryption or decryption process.
   - It provides feedback on the success or failure of each operation, including notifications for incorrect passwords or file tampering attempts.

