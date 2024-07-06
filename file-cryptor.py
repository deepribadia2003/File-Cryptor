import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey, InvalidSignature
import os
import re
import struct

class FileCryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("File Cryptor")

        # Styling
        self.root.configure(bg='#f0f0f0')  # Set background color
        self.root.geometry('800x600')  # Set window size

        # Fonts
        self.title_font = ('MS Serif', 36, 'bold')
        self.label_font = ('Times New Roman', 16)
        self.button_font = ('Helvetica', 12, 'bold')
        self.output_font = ('Courier', 10)  # Monospaced font for console output

        # Variables
        self.file_path = ""
        self.password = tk.StringVar()
        self.password.trace_add('write', self.limit_password_length)  # Limit password length
        self.console_output = tk.Text(root, height=10, width=50, font=self.output_font, wrap=tk.WORD, state=tk.DISABLED)

        # Widgets
        self.title_label = tk.Label(root, text="File Cryptor", font=self.title_font, bg='#f0f0f0', fg='#333')
        self.title_label.pack(pady=20)

        self.file_btn = tk.Button(root, text="Select File", command=self.select_file, font=self.button_font, bg='#2196F3', fg='white', padx=10, pady=5, relief=tk.RAISED)
        self.file_btn.pack()

        # Add padding between "Select File" button and "Enter Password" label
        tk.Label(root, text="").pack()

        self.pass_label = tk.Label(root, text="Enter Password (up to 20 characters):", font=self.label_font, bg='#f0f0f0', fg='#333')
        self.pass_label.pack()

        self.pass_entry = tk.Entry(root, show="*", textvariable=self.password, font=self.label_font, width=20)
        self.pass_entry.pack()

        self.encrypt_btn = tk.Button(root, text="Encrypt", command=self.encrypt_file, font=self.button_font, bg='#4CAF50', fg='white', padx=10, pady=5, relief=tk.RAISED)
        self.encrypt_btn.pack(pady=10)

        self.decrypt_btn = tk.Button(root, text="Decrypt", command=self.decrypt_file, font=self.button_font, bg='#FF5722', fg='white', padx=10, pady=5, relief=tk.RAISED)
        self.decrypt_btn.pack(pady=10)

        self.console_output.pack(pady=20)  # Pack the console output text widget

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        self.update_console_output(f"Selected file: {self.file_path}")

    def limit_password_length(self, *args):
        if len(self.password.get()) > 20:
            self.password.set(self.password.get()[:20])

    def validate_password(self, password):
        # Validate length <= 20 (allow any characters)
        if len(password) > 20:
            return False
        return True

    def update_console_output(self, message):
        self.console_output.config(state=tk.NORMAL)  # Enable editing
        self.console_output.insert(tk.END, message + "\n")  # Append message
        self.console_output.config(state=tk.DISABLED)  # Disable editing
        self.console_output.see(tk.END)  # Scroll to the end

    def clear_password(self):
        self.password.set('')

    def delete_original_file(self):
        try:
            os.remove(self.file_path)
            self.update_console_output(f"Original file deleted: {self.file_path}")
            self.file_path = ""  # Reset file path
        except Exception as e:
            messagebox.showerror("Deletion Error", str(e))
            self.update_console_output(f"Deletion error: {e}")

    def encrypt_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file.")
            return
        password = self.password.get()

        if not password:
            messagebox.showerror("Error", "Please enter the password.")
            self.update_console_output("Please enter the password.")
            return

        if not self.validate_password(password):
            messagebox.showerror("Error", "Password length should be up to 20 characters.")
            return

        try:
            # Generate a salt and derive a key using PBKDF2
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())

            # Encrypt the file
            with open(self.file_path, 'rb') as f:
                data = f.read()

            # Pad the data
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Store original file extension
            original_extension = os.path.splitext(self.file_path)[1].encode()
            extension_length = len(original_extension)

            # Write encrypted data to a new file
            with open(self.file_path + '.enc', 'wb') as f:
                f.write(salt + iv + struct.pack('B', extension_length) + original_extension + encrypted_data)

            self.update_console_output("File encrypted successfully.")
            print("File encrypted successfully.")
            self.delete_original_file()

        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            self.update_console_output(f"Encryption error: {e}")
        finally:
            self.clear_password()

    def decrypt_file(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file.")
            return
        password = self.password.get()

        if not password:
            messagebox.showerror("Error", "Please enter the password.")
            self.update_console_output("Please enter the password.")
            return

        if not self.validate_password(password):
            messagebox.showerror("Error", "Password length should be up to 20 characters.")
            return

        try:
            # Read the encrypted file
            with open(self.file_path, 'rb') as f:
                data = f.read()

            salt = data[:16]
            iv = data[16:32]
            metadata_start = 32
            extension_length = struct.unpack('B', data[metadata_start:metadata_start + 1])[0]
            metadata_end = metadata_start + 1 + extension_length
            original_extension = data[metadata_start + 1:metadata_end]
            encrypted_data = data[metadata_end:]

            # Derive the key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())

            # Decrypt the file
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Unpad the decrypted data
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_padded_data = unpadder.update(decrypted_data) + unpadder.finalize()

            # Write decrypted data to a new file with the original extension
            decrypted_file_path = os.path.splitext(self.file_path)[0] + original_extension.decode()
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_padded_data)

            self.update_console_output("File decrypted successfully.")
            print("File decrypted successfully.")
            self.delete_original_file()

        except (InvalidKey, ValueError):
            messagebox.showerror("Decryption Error", "Wrong password.")
            self.update_console_output("Wrong password.")        
        except InvalidSignature:
            messagebox.showerror("Decryption Error", "Invalid signature: the file may have been tampered with.")
            self.update_console_output("Invalid signature: the file may have been tampered with.")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            self.update_console_output(f"Decryption error: {e}")
        finally:
            self.clear_password()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileCryptor(root)
    root.mainloop()
