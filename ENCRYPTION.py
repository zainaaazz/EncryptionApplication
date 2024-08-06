import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from Cryptodome.Cipher import DES
from Cryptodome.Random import get_random_bytes
import os
import hashlib


class EncryptionExample:
    def __init__(self, master):
        self.master = master
        self.key = None

    def create_gui(self):
        self.master.title("Encryption")
        

        # Create UI elements
        self.heading_label = tk.Label(
            self.master, text="Encryption", font=("Helvetica", 16, "bold")
        )
        self.heading_label.pack(pady=10)

        self.file_frame = tk.Frame(self.master)
        self.file_frame.pack(pady=10)

        self.select_label = tk.Label(self.file_frame, text="Select File:")
        self.select_label.pack(side=tk.LEFT)

        self.file_path_var = tk.StringVar()
        self.file_path_entry = tk.Entry(
            self.file_frame, textvariable=self.file_path_var, width=30
        )
        self.file_path_entry.pack(side=tk.LEFT)

        self.browse_button = tk.Button(
            self.file_frame, text="Browse", command=self.browse_file
        )
        self.browse_button.pack(side=tk.LEFT)
        
        self.key_frame = tk.Frame(self.master)
        self.key_frame.pack(pady=10)

        self.key_label = tk.Label(self.key_frame, text="Encryption Key:")
        self.key_label.pack(side=tk.LEFT)

        self.key_var = tk.StringVar()
        self.key_entry = tk.Entry(self.key_frame, textvariable=self.key_var, width=30)
        self.key_entry.pack(side=tk.LEFT)
        
        global v 
        v = tk.IntVar()

        tk.Radiobutton(root, 
                    text="DES",
                    padx = 20, 
                    variable=v, 
                    value=1).pack(pady=5)

        tk.Radiobutton(root, 
                    text="Own Algorithm",
                    padx = 20, 
                    variable=v, 
                    value=2).pack(pady=5)
        
        self.encrypt_button = tk.Button(
            self.master, text="Encrypt", command=self.encrypt_file
        )
        self.encrypt_button.pack(pady=10)
        
        self.decrypt_button = tk.Button(
            self.master, text="Decrypt", command=self.decrypt_file
        )
        self.decrypt_button.pack(pady=10)

    def browse_file(self):
        try:
            file_path = filedialog.askopenfilename()
            self.file_path_var.set(file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to browse file: {str(e)}")
        

    def encrypt_file(self):
        file_path = self.file_path_var.get()
        key = self.key_var.get()

        if file_path and key:
            
            if v.get() == 1:
                try:
                    # Read the contents of the file
                    with open(file_path, "rb") as file:
                        plaintext = file.read()

                    # Generate a random 8-byte initialization vector (IV)
                    iv = get_random_bytes(8)

                    # Create a DES cipher object with the key and mode
                    cipher = DES.new(key.encode(), DES.MODE_CBC, iv)

                    # Pad the plaintext to be a multiple of 8 bytes
                    padded_plaintext = self.pad(plaintext)

                    # Encrypt the padded plaintext
                    ciphertext = cipher.encrypt(padded_plaintext)

                    # Create a new file path for the encrypted file
                    encrypted_file_path = file_path + ".encrypted"

                    # Write the IV and ciphertext to the new file
                    with open(encrypted_file_path, "wb") as file:
                        file.write(iv + ciphertext)

                    # Delete the original file
                    os.remove(file_path)
                    
                    messagebox.showinfo("Success", "File encrypted successfully")
                    self.clear_textboxes()
                except Exception as e:
                    messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            else:
                # Create a new file path for the encrypted file
                encrypted_file_path = file_path + ".encrypted"

                # Hash the password
                hashed_password = hashlib.sha256(key.encode()).digest()

                with open(file_path, "rb") as file_in, open(encrypted_file_path, "wb") as file_out:
                    while True:
                        # Read a chunk of data from the input file
                        chunk = file_in.read(1024)
                        if not chunk:
                            break
                        # Encrypted chunks
                        encrypted_chunk = bytearray() #create an array of bytes
                        for byte in chunk:
                            # XOR each byte of the data with a byte from the hashed password
                            encrypted_byte = byte ^ hashed_password[len(encrypted_chunk) % len(hashed_password)]
                            encrypted_chunk.append(encrypted_byte)
                        # Write encrypted file to the output file.
                        file_out.write(bytes(encrypted_chunk))

                # Delete the original file
                os.remove(file_path)

                messagebox.showinfo("", "ENCRYPTED SUCCESSFULLY")
                self.clear_textboxes()
            
        else:
            messagebox.showwarning("Warning", "Please select a file and enter a key")

    def decrypt_file(self):
        file_path = self.file_path_var.get()
        key = self.key_var.get()

        if file_path and key:
            if v.get() == 1:
                try:
                    # Read the contents of the encrypted file
                    with open(file_path, 'rb') as file:
                        ciphertext = file.read()

                    # Extract the IV and ciphertext from the file
                    iv = ciphertext[:8]
                    ciphertext = ciphertext[8:]

                    # Create a DES cipher object with the key and mode
                    cipher = DES.new(key.encode(), DES.MODE_CBC, iv)

                    # Decrypt the ciphertext
                    decrypted_text = cipher.decrypt(ciphertext)

                    # Unpad the decrypted text
                    unpadded_text = self.unpad(decrypted_text)

                    # Create a new file path for the decrypted file
                    decrypted_file_path = file_path[:-10]

                    # Write the decrypted text to the new file
                    with open(decrypted_file_path, 'wb') as file:
                        file.write(unpadded_text)

                    messagebox.showinfo("Success", "File decrypted successfully")
                    self.clear_textboxes()
                    
                    # Delete the original file
                    os.remove(file_path)
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            else:
                # Hash the password
                hashed_password = hashlib.sha256(key.encode()).digest()

                # Create a new file path for the decrypted file
                decrypted_file_path = os.path.splitext(file_path)[0].replace(".encrypted", "")

                with open(file_path, "rb") as file_in, open(decrypted_file_path, "wb") as file_out:
                    while True:
                        chunk = file_in.read(1024)
                        if not chunk:
                            break
                        decrypted_chunk = bytearray()
                        for byte in chunk:
                            decrypted_byte = byte ^ hashed_password[len(decrypted_chunk) % len(hashed_password)]
                            decrypted_chunk.append(decrypted_byte)
                        file_out.write(bytes(decrypted_chunk))


            # Delete the original file
            os.remove(file_path)

            messagebox.showinfo("", "DECRYPTED SUCCESSFULLY")
            self.clear_textboxes()
                
        else:
            messagebox.showwarning("Warning", "Please select a file and enter a key")

                
    def pad(self, data):
        padding_size = DES.block_size - (len(data) % DES.block_size)
        padding = bytes([padding_size] * padding_size)
        return data + padding

    def unpad(self, data):
        padding_size = data[-1]
        return data[:-padding_size]

    def clear_textboxes(self):
        self.file_path_var.set("")
        self.key_var.set("")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionExample(root)
    app.create_gui()
    root.mainloop()


