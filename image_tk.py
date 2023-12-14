import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from PIL import Image, ImageTk
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, Blowfish

# Constants
AES_BLOCK_SIZE = 16  # AES block size (in bytes)
BLOWFISH_BLOCK_SIZE = 8  # Blowfish block size (in bytes)

class SteganographyGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Hybrid Image Steganography")
        self.master.geometry("600x300")

        # Frames
        self.frame = tk.Frame(self.master)
        self.frame.pack(pady=20)

        # Labels
        tk.Label(self.frame, text="Choose Cover Image:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        tk.Label(self.frame, text="Choose Secret Image:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        tk.Label(self.frame, text="Output Stego Image:").grid(row=2, column=0, padx=10, pady=10, sticky="e")

        # Entries
        self.cover_image_path_entry = tk.Entry(self.frame, width=40)
        self.secret_image_path_entry = tk.Entry(self.frame, width=40)
        self.output_stego_image_path_entry = tk.Entry(self.frame, width=40)

        self.cover_image_path_entry.grid(row=0, column=1, padx=10, pady=10)
        self.secret_image_path_entry.grid(row=1, column=1, padx=10, pady=10)
        self.output_stego_image_path_entry.grid(row=2, column=1, padx=10, pady=10)

        # Buttons
        tk.Button(self.frame, text="Choose", command=self.choose_cover_image).grid(row=0, column=2, padx=10, pady=10)
        tk.Button(self.frame, text="Choose", command=self.choose_secret_image).grid(row=1, column=2, padx=10, pady=10)
        tk.Button(self.frame, text="Choose", command=self.choose_output_stego_image).grid(row=2, column=2, padx=10, pady=10)

        tk.Button(self.master, text="Encode", command=self.encode).pack()


    def choose_cover_image(self):
        filename = filedialog.askopenfilename(initialdir="/", title="Select Cover Image")
        self.cover_image_path_entry.delete(0, tk.END)
        self.cover_image_path_entry.insert(0, filename)

    def choose_secret_image(self):
        filename = filedialog.askopenfilename(initialdir="/", title="Select Secret Image")
        self.secret_image_path_entry.delete(0, tk.END)
        self.secret_image_path_entry.insert(0, filename)

    def choose_output_stego_image(self):
        filename = filedialog.asksaveasfilename(initialdir="/", title="Save As", defaultextension=".png", filetypes=[("PNG files", "*.png")])
        self.output_stego_image_path_entry.delete(0, tk.END)
        self.output_stego_image_path_entry.insert(0, filename)

    def encode(self):
        cover_image_path = self.cover_image_path_entry.get()
        secret_image_path = self.secret_image_path_entry.get()
        output_stego_image_path = self.output_stego_image_path_entry.get()

        if not (cover_image_path and secret_image_path and output_stego_image_path):
            messagebox.showerror("Error", "Please choose cover image, secret image, and output stego image.")
            return

        try:
            cover_image = Image.open(cover_image_path).convert("RGB")
            stego_image, aes_key, blowfish_key = embed_message_in_image(cover_image, secret_image_path)

            stego_image.save(output_stego_image_path)
            tk.messagebox.showinfo("Success", "Secret image embedded and stego image saved successfully!")

            with open(output_stego_image_path + ".aes_key", "wb") as aes_key_file:
                aes_key_file.write(aes_key)

            with open(output_stego_image_path + ".blowfish_key", "wb") as blowfish_key_file:
                blowfish_key_file.write(blowfish_key)

        except Exception as e:
            tk.messagebox.showerror("Error", f"An error occurred: {e}")

def embed_message_in_image(image, secret_image_path):
    with open(secret_image_path, "rb") as secret_image_file:
        secret_image_data = secret_image_file.read()

    aes_key = get_random_bytes(AES_BLOCK_SIZE)
    blowfish_key = get_random_bytes(BLOWFISH_BLOCK_SIZE)

    encrypted_secret_image_aes = encrypt_data_aes(aes_key, secret_image_data)
    encrypted_secret_image = encrypt_data_blowfish(blowfish_key, encrypted_secret_image_aes)

    aes_image_length = len(encrypted_secret_image_aes).to_bytes(4, byteorder="big")
    blowfish_image_length = len(encrypted_secret_image).to_bytes(4, byteorder="big")

    data_bin = "".join(format(byte, "08b") for byte in aes_image_length + blowfish_image_length + encrypted_secret_image)

    pixels = image.load()
    pixel_index = 0
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = pixels[i, j]

            if pixel_index < len(data_bin):
                r = r & ~1 | int(data_bin[pixel_index])
                pixel_index += 1
            if pixel_index < len(data_bin):
                g = g & ~1 | int(data_bin[pixel_index])
                pixel_index += 1
            if pixel_index < len(data_bin):
                b = b & ~1 | int(data_bin[pixel_index])
                pixel_index += 1

            pixels[i, j] = (r, g, b)

    return image, aes_key, blowfish_key

def encrypt_data_aes(key, data):
    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext

def encrypt_data_blowfish(key, data):
    cipher = Blowfish.new(key, Blowfish.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyGUI(root)
    root.mainloop()
