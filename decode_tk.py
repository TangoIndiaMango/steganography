import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES, Blowfish
import threading
import time

AES_BLOCK_SIZE = 16  # AES block size (in bytes)
BLOWFISH_BLOCK_SIZE = 8  # Blowfish block size (in bytes)

def decrypt_data_aes(key, data):
    iv = data[:AES_BLOCK_SIZE]
    ciphertext = data[AES_BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)

def decrypt_data_blowfish(key, data):
    iv = data[:BLOWFISH_BLOCK_SIZE]
    ciphertext = data[BLOWFISH_BLOCK_SIZE:]
    cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)

def extract_message_from_image(image, aes_key, blowfish_key, output_secret_image_path):
    data_bin = ""
    pixels = image.load()
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = pixels[i, j]
            data_bin += str(r & 1)
            data_bin += str(g & 1)
            data_bin += str(b & 1)

    data = bytes(int(data_bin[i: i + 8], 2) for i in range(0, len(data_bin), 8))

    aes_image_length = int.from_bytes(data[:4], byteorder="big")
    blowfish_image_length = int.from_bytes(data[4:8], byteorder="big")

    encrypted_image = data[8: 8 + aes_image_length + blowfish_image_length]

    decrypted_secret_image_aes = decrypt_data_blowfish(blowfish_key, encrypted_image)
    decrypted_secret_image_data = decrypt_data_aes(aes_key, decrypted_secret_image_aes)

    with open(output_secret_image_path, "wb") as output_image_file:
        output_image_file.write(decrypted_secret_image_data)

    messagebox.showinfo("Success", "Secret image extracted and saved successfully!")

class SteganographyGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Hybrid Image Steganography")
        self.master.geometry("500x400")

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.master, text="Choose Stego Image:").grid(row=0, column=0, padx=10, pady=10)
        tk.Label(self.master, text="Choose AES Key File:").grid(row=1, column=0, padx=10, pady=10)
        tk.Label(self.master, text="Choose Blowfish Key File:").grid(row=2, column=0, padx=10, pady=10)
        tk.Label(self.master, text="Output Secret Image:").grid(row=3, column=0, padx=10, pady=10)

        self.stego_image_path_entry = tk.Entry(self.master, width=40)
        self.aes_key_path_entry = tk.Entry(self.master, width=40)
        self.blowfish_key_path_entry = tk.Entry(self.master, width=40)
        self.output_secret_image_path_entry = tk.Entry(self.master, width=40)

        self.stego_image_path_entry.grid(row=0, column=1, padx=10, pady=10)
        self.aes_key_path_entry.grid(row=1, column=1, padx=10, pady=10)
        self.blowfish_key_path_entry.grid(row=2, column=1, padx=10, pady=10)
        self.output_secret_image_path_entry.grid(row=3, column=1, padx=10, pady=10)

        tk.Button(self.master, text="Choose", command=self.choose_stego_image).grid(row=0, column=2, padx=10, pady=10)
        tk.Button(self.master, text="Choose", command=self.choose_aes_key).grid(row=1, column=2, padx=10, pady=10)
        tk.Button(self.master, text="Choose", command=self.choose_blowfish_key).grid(row=2, column=2, padx=10, pady=10)
        tk.Button(self.master, text="Choose", command=self.choose_output_secret_image).grid(row=3, column=2, padx=10, pady=10)

        tk.Button(self.master, text="Decode", command=self.decode).grid(row=4, column=0, columnspan=3, pady=20)

    def choose_stego_image(self):
        filename = filedialog.askopenfilename(initialdir="/", title="Select Stego Image")
        self.stego_image_path_entry.delete(0, tk.END)
        self.stego_image_path_entry.insert(0, filename)

    def choose_aes_key(self):
        filename = filedialog.askopenfilename(initialdir="/", title="Select AES Key File")
        self.aes_key_path_entry.delete(0, tk.END)
        self.aes_key_path_entry.insert(0, filename)

    def choose_blowfish_key(self):
        filename = filedialog.askopenfilename(initialdir="/", title="Select Blowfish Key File")
        self.blowfish_key_path_entry.delete(0, tk.END)
        self.blowfish_key_path_entry.insert(0, filename)

    def choose_output_secret_image(self):
        filename = filedialog.asksaveasfilename(initialdir="/", title="Save Output Secret Image As", filetypes=[("PNG files", "*.png")])
        self.output_secret_image_path_entry.delete(0, tk.END)
        self.output_secret_image_path_entry.insert(0, filename)

    def decode(self):
        stego_image_path = self.stego_image_path_entry.get()
        aes_key_file_path = self.aes_key_path_entry.get()
        blowfish_key_file_path = self.blowfish_key_path_entry.get()
        output_secret_image_path = self.output_secret_image_path_entry.get()
        try:
            start_time = time.time()
            stego_image = Image.open(stego_image_path)
            with open(aes_key_file_path, "rb") as aes_key_file:
                aes_key = aes_key_file.read()
            with open(blowfish_key_file_path, "rb") as blowfish_key_file:
                blowfish_key = blowfish_key_file.read()
            

            extract_message_from_image(stego_image, aes_key, blowfish_key, output_secret_image_path)
            end_time = time.time() - start_time
            print(f"Time taken for decoding: {end_time:.4f} seconds")
            print("Done decoding")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyGUI(root)
    root.mainloop()
