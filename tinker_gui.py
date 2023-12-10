import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
from Crypto.Cipher import Blowfish, AES
from Crypto.Random import get_random_bytes
import time

# Constants
BLOCK_SIZE_AES = 16  # AES block size (in bytes)
BLOCK_SIZE_BLOWFISH = 8  # Blowfish block size (in bytes)


def encrypt_data_aes(key, data):
    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext


def decrypt_data_aes(key, data):
    iv = data[:BLOCK_SIZE_AES]
    ciphertext = data[BLOCK_SIZE_AES:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)


def encrypt_data_blowfish(key, data):
    cipher = Blowfish.new(key, Blowfish.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext


def decrypt_data_blowfish(key, data):
    iv = data[:BLOCK_SIZE_BLOWFISH]
    ciphertext = data[BLOCK_SIZE_BLOWFISH:]
    cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)


def embed_message_in_image(image, secret_image_path, algorithm):
    # Read the secret image and convert it to bytes
    with open(secret_image_path, "rb") as secret_image_file:
        secret_image_data = secret_image_file.read()

    if algorithm == 'AES':
        key = get_random_bytes(BLOCK_SIZE_AES)
        encrypted_secret_image = encrypt_data_aes(key, secret_image_data)
    elif algorithm == 'Blowfish':
        key = get_random_bytes(BLOCK_SIZE_BLOWFISH)
        encrypted_secret_image = encrypt_data_blowfish(key, secret_image_data)

    image_length = len(encrypted_secret_image).to_bytes(4, byteorder="big")
    data_bin = "".join(format(byte, "08b") for byte in image_length + encrypted_secret_image)

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

    return image, key


def extract_message_from_image(image, key, output_secret_image_path, algorithm):
    data_bin = ""
    pixels = image.load()
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = pixels[i, j]
            data_bin += str(r & 1)
            data_bin += str(g & 1)
            data_bin += str(b & 1)

    data = bytes(int(data_bin[i: i + 8], 2) for i in range(0, len(data_bin), 8))

    image_length = int.from_bytes(data[:4], byteorder="big")
    encrypted_image = data[4: 4 + image_length]

    if algorithm == 'AES':
        decrypted_secret_image_data = decrypt_data_aes(key, encrypted_image)
    elif algorithm == 'Blowfish':
        decrypted_secret_image_data = decrypt_data_blowfish(key, encrypted_image)

    with open(output_secret_image_path, "wb") as output_image_file:
        output_image_file.write(decrypted_secret_image_data)

    print("Secret image extracted and saved successfully!")


def encode_button_clicked(window, cover_image_path, secret_image_path, output_stego_image_path, algorithm):
    cover_image = Image.open(cover_image_path).convert("RGB")

    start_time = time.time()
    try:
        stego_image, key = embed_message_in_image(cover_image, secret_image_path, algorithm)
        stego_image.save(output_stego_image_path)
        print("Secret image embedded and stego image saved successfully!")
        elapsed_time = time.time() - start_time
        print(f"Time taken for encoding: {elapsed_time:.4f} seconds")
        # Save the key to a file
        with open(output_stego_image_path + ".key", "wb") as key_file:
            key_file.write(key)
    except Exception as e:
        print(f"Error: {e}")

    window.destroy()


def decode_button_clicked(window, cover_image_path, output_secret_image_path, algorithm):
    stego_image = Image.open(cover_image_path)

    key_file_path = filedialog.askopenfilename(initialdir="/", title="Select key file")
    with open(key_file_path, "rb") as key_file:
        key = key_file.read()

    start_time = time.time()
    try:
        extract_message_from_image(stego_image, key, output_secret_image_path, algorithm)
        elapsed_time = time.time() - start_time
        print(f"Time taken for decoding: {elapsed_time:.4f} seconds")
    except Exception as e:
        print(f"Error: {e}")

    window.destroy()


def open_file_dialog(entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file")
    entry.delete(0, tk.END)
    entry.insert(0, filename)


def create_gui():
    root = tk.Tk()
    root.title("Image Steganography")

    cover_image_path_entry = tk.Entry(root, width=50)
    secret_image_path_entry = tk.Entry(root, width=50)
    output_stego_image_path_entry = tk.Entry(root, width=50)

    cover_image_path_button = tk.Button(
        root, text="Choose Cover Image", command=lambda: open_file_dialog(cover_image_path_entry)
    )
    secret_image_path_button = tk.Button(
        root, text="Choose Secret Image", command=lambda: open_file_dialog(secret_image_path_entry)
    )
    output_stego_image_path_button = tk.Button(
        root,
        text="Choose Output Stego Image",
        command=lambda: open_file_dialog(output_stego_image_path_entry),
    )

    algorithm_label = tk.Label(root, text="Choose Algorithm:")
    algorithm_var = tk.StringVar()
    algorithm_var.set("AES")  # Default value
    algorithm_menu = tk.OptionMenu(root, algorithm_var, "AES", "Blowfish")

    encode_button = tk.Button(
        root,
        text="Encode",
        command=lambda: encode_button_clicked(
            root,
            cover_image_path_entry.get(),
            secret_image_path_entry.get(),
            output_stego_image_path_entry.get(),
            algorithm_var.get(),
        ),
    )

    decode_button = tk.Button(
        root,
        text="Decode",
        command=lambda: decode_button_clicked(
            root, cover_image_path_entry.get(), output_stego_image_path_entry.get(), algorithm_var.get()
        ),
    )

    cover_image_path_entry.grid(row=0, column=0, padx=10, pady=10)
    secret_image_path_entry.grid(row=1, column=0, padx=10, pady=10)
    output_stego_image_path_entry.grid(row=2, column=0, padx=10, pady=10)

    cover_image_path_button.grid(row=0, column=1, padx=10, pady=10)
    secret_image_path_button.grid(row=1, column=1, padx=10, pady=10)
    output_stego_image_path_button.grid(row=2, column=1, padx=10, pady=10)

    algorithm_label.grid(row=3, column=0, columnspan=2)
    algorithm_menu.grid(row=4, column=0, columnspan=2, pady=10)

    encode_button.grid(row=5, column=0, columnspan=2, pady=10)
    decode_button.grid(row=6, column=0, columnspan=2, pady=10)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
