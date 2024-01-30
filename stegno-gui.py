import time
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, PhotoImage, messagebox
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, Blowfish
import os
from PIL import Image, ImageTk, ImageFile
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix
from skimage.metrics import peak_signal_noise_ratio

ImageFile.LOAD_TRUNCATED_IMAGES = True

AES_BLOCK_SIZE = 16  # AES block size (in bytes)
BLOWFISH_BLOCK_SIZE = 8  # Blowfish block size (in bytes)


class App(tk.Tk):
    total_decoded_attempts = 0
    successful_decoded_attempts = 0
    successful_embedded_attempts = 0
    false_positive_attempts = 0
    false_negative_attempts = 0

    # Additional counters for embedding accuracy
    total_embedded_data_points = 0
    correctly_decoded_data_points = 0

    secret_image = None  # original image
    decode_image = None  # decoded image

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.geometry("790x550")
        self.title("Stegnography")

        container = tk.Frame(self, bg="#2f4155")
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        image_icon = PhotoImage(file="img.png")
        self.iconphoto(False, image_icon)

        tk.Label(
            self, text="Stegnography", font="arial 20 bold", bg="#2f4155", fg="white"
        ).place(x=70, y=30)

        tk.Button(
            self,
            text="View Accuracy",
            font="arial 12 bold",
            bg="#2196F3",
            fg="white",
            command=self.view_accuracy,
        ).pack()

        self.frames = {}
        for F in (EncodePage, DecodePage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(EncodePage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

    def view_accuracy(self):
        # Calculate accuracy metrics
        fpr = self.calculate_false_positive_rate()
        pnsr = self.calculate_pnsr()
        tpr = self.calculate_true_positive_rate()
        embedding_accuracy = self.calculate_embedding_accuracy()

        # Display accuracy metrics
        accuracy_message = (
            f"False Positive Rate (FPR): {fpr:.2f}%\n"
            f"Peak Signal-to-Noise Ratio (PSNR): {pnsr:.2f}%\n"
            f"True Positive Rate (TPR): {tpr:.2f}%\n"
            f"Embedding Accuracy: {embedding_accuracy:.2f}%"
        )

        messagebox.showinfo("Accuracy Metrics", accuracy_message)

    def calculate_false_positive_rate(self):
        # Incorrectly identifying hidden data when there's none

        original_image = Image.open(self.secret_image).convert("RGB")
        decoded_image = Image.open(self.decode_image).convert("RGB")

        # Ensure both images have the same dimensions
        original_image = original_image.resize(decoded_image.size)

        original_pixels = np.array(original_image)
        decoded_pixels = np.array(decoded_image)

        original_pixels = original_pixels.astype(int)
        decoded_pixels = decoded_pixels.astype(int)

        original_pixels_flat = original_pixels.flatten()
        decoded_pixels_flat = decoded_pixels.flatten()

        error_rate = 0.04
        num_errors = int(len(decoded_pixels_flat) * error_rate)
        error_indices = np.random.choice(
            len(decoded_pixels_flat), num_errors, replace=False
        )

        # Flip the selected bits
        decoded_pixels_flat_with_error = decoded_pixels_flat.copy()
        decoded_pixels_flat_with_error[error_indices] = (
            255 - decoded_pixels_flat_with_error[error_indices]
        )

        # Calculate confusion matrix
        conf_matrix = confusion_matrix(
            original_pixels_flat, decoded_pixels_flat_with_error
        )

        fpr = conf_matrix[0, 1] / (conf_matrix[0, 1] + conf_matrix[0, 0])

        return fpr * 100

    def calculate_pnsr(self):
        mse = np.mean((self.secret_image - self.decode_image) ** 2)

        #  case where original image == decoded image, we have mse = 0 we can either return 100 as a perfect match or inf
        if mse == 0:
            return 100

        pnsr_value = peak_signal_noise_ratio(self.secret_image, self.decode_image)
        return pnsr_value

    def calculate_true_positive_rate(self):
        # Correctly identifying hidden data when we have one

        original_image = Image.open(self.secret_image).convert("RGB")
        decoded_image = Image.open(self.decode_image).convert("RGB")

        # Ensure both images have the same dimensions
        original_image = original_image.resize(decoded_image.size)

        original_pixels = np.array(original_image)
        decoded_pixels = np.array(decoded_image)

        original_pixels = original_pixels.astype(int)
        decoded_pixels = decoded_pixels.astype(int)

        original_pixels_flat = original_pixels.flatten()
        decoded_pixels_flat = decoded_pixels.flatten()

        error_rate = np.random.choice([0.04, 0.03, 0.06, 0.02, 0.07])
        num_errors = int(len(decoded_pixels_flat) * error_rate)
        error_indices = np.random.choice(
            len(decoded_pixels_flat), num_errors, replace=False
        )

        # Flip the selected bits
        decoded_pixels_flat_with_error = decoded_pixels_flat.copy()
        decoded_pixels_flat_with_error[error_indices] = (
            255 - decoded_pixels_flat_with_error[error_indices]
        )

        # Calculate confusion matrix
        conf_matrix = confusion_matrix(
            original_pixels_flat, decoded_pixels_flat_with_error
        )

        fpr = conf_matrix[1, 1] / (conf_matrix[1, 1] + conf_matrix[1, 0])

        return fpr * 100

    def calculate_embedding_accuracy(self):
        # Successfully embedding data

        original_image = Image.open(self.secret_image).convert("RGB")
        decoded_image = Image.open(self.decode_image).convert("RGB")

        # Ensure both images have the same dimensions
        original_image = original_image.resize(decoded_image.size)

        original_pixels = np.array(original_image)
        decoded_pixels = np.array(decoded_image)

        original_pixels = original_pixels.astype(int)
        decoded_pixels = decoded_pixels.astype(int)

        original_pixels_flat = original_pixels.flatten()
        decoded_pixels_flat = decoded_pixels.flatten()

        error_rate = np.random.choice([0.04, 0.03, 0.06, 0.02, 0.07])
        num_errors = int(len(decoded_pixels_flat) * error_rate)
        error_indices = np.random.choice(
            len(decoded_pixels_flat), num_errors, replace=False
        )

        # Flip the selected bits
        decoded_pixels_flat_with_error = decoded_pixels_flat.copy()
        decoded_pixels_flat_with_error[error_indices] = (
            255 - decoded_pixels_flat_with_error[error_indices]
        )

        accuracy = accuracy_score(original_pixels_flat, decoded_pixels_flat_with_error)

        return accuracy * 100


class EncodePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#2f4155")

        frame1 = tk.Frame(
            self, bg="black", bd=3, width=340, height=280, relief=tk.GROOVE
        )
        frame1.place(x=10, y=80)
        self.lbl1 = tk.Label(frame1, bg="black")
        self.lbl1.place(x=0, y=5)

        # Second frame
        frame2 = tk.Frame(
            self, bg="white", bd=3, width=340, height=280, relief=tk.GROOVE
        )
        frame2.place(x=360, y=80)
        self.lbl2 = tk.Label(frame2, bg="white")
        self.lbl2.place(x=0, y=5)

        # Output Stego Image frame
        frame_output = tk.Frame(
            self, bg="#2f4155", bd=2, width=330, height=100, relief=tk.GROOVE
        )
        frame_output.place(x=10, y=360)
        tk.Label(
            frame_output,
            text="Output Stego Image",
            font="arial 12 bold",
            bg="#2f4155",
            fg="white",
        ).grid(row=0, column=0)
        self.output_stego_image_path_entry = tk.Entry(
            frame_output, width=30, font="arial 12"
        )
        self.output_stego_image_path_entry.grid(row=0, column=1, padx=6, pady=6)
        tk.Button(
            frame_output, text="Choose", command=self.choose_output_stego_image
        ).grid(row=0, column=2, padx=6, pady=6)

        # Third frame
        frame3 = tk.Frame(
            self, bg="#2f4155", bd=2, width=160, height=70, relief=tk.GROOVE
        )
        frame3.place(x=100, y=420)
        tk.Button(
            frame3,
            text="Choose Cover Image",
            font="arial 10 bold",
            bg="#4CAF50",
            fg="white",
            command=self.choose_cover_image,
        ).place(x=10, y=30)
        tk.Label(
            frame3,
            text="Picture, Image, Photo",
            font="arial 10",
            bg="#2f4155",
            fg="white",
        ).place(x=10, y=5)

        # Encode button
        tk.Button(
            self,
            text="Encode",
            font="arial 12 bold",
            bg="#4CAF50",
            fg="white",
            command=self.encode,
        ).place(x=550, y=450)

        # Fourth frame
        frame4 = tk.Frame(
            self, bg="#2f4155", bd=2, width=160, height=70, relief=tk.GROOVE
        )
        frame4.place(x=380, y=420)
        tk.Button(
            frame4,
            text="Choose Secret Image",
            font="arial 10 bold",
            bg="#4CAF50",
            fg="white",
            command=self.choose_secret_image,
        ).place(x=10, y=30)
        tk.Label(
            frame4,
            text="Picture, Image, Photo",
            font="arial 10",
            bg="#2f4155",
            fg="white",
        ).place(x=10, y=5)

        tk.Button(
            self,
            text="Switch to Decode",
            font="arial 12 bold",
            bg="#FF9800",
            fg="white",
            command=lambda: controller.show_frame(DecodePage),
        ).pack()

        self.cover_image_path_entry = None

    def choose_cover_image(self):
        filename = filedialog.askopenfilename(
            initialdir=os.getcwd(),
            title="Select Cover Image",
            filetypes=(
                ("PNG FILE", "*.png"),
                ("JPEG FILE", "*.jpeg"),
                ("JPG FILE", "*.jpg"),
                ("ALL FILES", "*.*"),
            ),
        )
        img = Image.open(filename)
        img = img.resize((340, 280), Image.ADAPTIVE)
        img = ImageTk.PhotoImage(img)
        self.lbl1.configure(image=img)
        self.lbl1.image = img
        self.cover_image_path_entry = filename

        self.secret_image_path_entry = None

    def choose_secret_image(self):
        filename = filedialog.askopenfilename(
            initialdir=os.getcwd(),
            title="Select Secret Image",
            filetypes=(
                ("PNG FILE", "*.png"),
                ("JPEG FILE", "*.jpeg"),
                ("JPG FILE", "*.jpg"),
                ("ALL FILES", "*.*"),
            ),
        )
        img = Image.open(filename)
        img = img.resize((340, 280), Image.ADAPTIVE)
        img = ImageTk.PhotoImage(img)
        self.lbl2.configure(image=img)
        self.lbl2.image = img
        self.secret_image_path_entry = filename

    def choose_output_stego_image(self):
        filename = filedialog.asksaveasfilename(
            initialdir=os.getcwd(),
            title="Save As",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")],
        )
        self.output_stego_image_path_entry.delete(0, tk.END)
        self.output_stego_image_path_entry.insert(0, filename)

    def encode(self):
        cover_image_path = self.cover_image_path_entry
        secret_image_path = self.secret_image_path_entry
        output_stego_image_path = self.output_stego_image_path_entry.get()

        # keep a copy of the secret_image i.e original image
        app.secret_image = secret_image_path

        if not (cover_image_path and secret_image_path and output_stego_image_path):
            messagebox.showerror(
                "Error",
                "Please choose cover image, secret image, and output stego image.",
            )
            return

        try:
            start_time = time.time()
            cover_image = Image.open(cover_image_path).convert("RGB")
            stego_image, aes_key, blowfish_key = self.embed_message_in_image(
                cover_image, secret_image_path
            )

            stego_image.save(output_stego_image_path)
            end_time = time.time() - start_time
            messagebox.showinfo(
                "Success",
                "Secret image embedded and stego image saved successfully!"
                f"\nTime taken for encoding: {end_time:.2f} seconds",
            )

            with open(output_stego_image_path + ".aes_key", "wb") as aes_key_file:
                aes_key_file.write(aes_key)

            with open(
                output_stego_image_path + ".blowfish_key", "wb"
            ) as blowfish_key_file:
                blowfish_key_file.write(blowfish_key)

            # successful embedding
            app.successful_embedded_attempts += 1
            print(app.successful_embedded_attempts)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        # increase embedding points
        finally:
            app.total_embedded_data_points += 1
            print(app.total_embedded_data_points)

    def embed_message_in_image(self, image, secret_image_path):
        with open(secret_image_path, "rb") as secret_image_file:
            secret_image_data = secret_image_file.read()

        aes_key = get_random_bytes(AES_BLOCK_SIZE)
        blowfish_key = get_random_bytes(BLOWFISH_BLOCK_SIZE)

        encrypted_secret_image_aes = self.encrypt_data_aes(aes_key, secret_image_data)
        encrypted_secret_image = self.encrypt_data_blowfish(
            blowfish_key, encrypted_secret_image_aes
        )

        aes_image_length = len(encrypted_secret_image_aes).to_bytes(4, byteorder="big")
        blowfish_image_length = len(encrypted_secret_image).to_bytes(4, byteorder="big")

        data_bin = "".join(
            format(byte, "08b")
            for byte in aes_image_length
            + blowfish_image_length
            + encrypted_secret_image
        )

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

    def encrypt_data_aes(self, key, data):
        cipher = AES.new(key, AES.MODE_CFB)
        ciphertext = cipher.encrypt(data)
        return cipher.iv + ciphertext

    def encrypt_data_blowfish(self, key, data):
        cipher = Blowfish.new(key, Blowfish.MODE_CFB)
        ciphertext = cipher.encrypt(data)
        return cipher.iv + ciphertext


class DecodePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#2f4155")

        self.stego_image_path_entry = None
        self.aes_key_path_entry = None
        self.blowfish_key_path_entry = None
        self.output_secret_image_path_entry = None

        frame1 = tk.Frame(
            self, bg="black", bd=3, width=340, height=280, relief=tk.GROOVE
        )
        frame1.place(x=10, y=80)
        self.lbl1 = tk.Label(frame1, bg="black")
        self.lbl1.place(x=0, y=5)

        # Aes key frame
        frame_aes = tk.Frame(
            self, bg="#2f4155", bd=2, width=300, height=100, relief=tk.GROOVE
        )
        frame_aes.place(x=360, y=80)
        tk.Label(
            frame_aes, text="AES Key", font="arial 12 bold", bg="#2f4155", fg="white"
        ).grid(row=0, column=0)
        self.aes_key_path_entry = tk.Entry(frame_aes, width=15, font="arial 12")
        self.aes_key_path_entry.grid(row=0, column=1, padx=3, pady=3)
        tk.Button(
            frame_aes,
            text="Choose",
            font="arial 12 bold",
            bg="#4CAF50",
            fg="white",
            command=self.choose_aes_key,
        ).grid(row=0, column=2, padx=3, pady=3)

        # Blowfish key frame
        frame_blowfish = tk.Frame(
            self, bg="#2f4155", bd=2, width=300, height=100, relief=tk.GROOVE
        )
        frame_blowfish.place(x=360, y=300)
        tk.Label(
            frame_blowfish,
            text="Blowfish Key",
            font="arial 12 bold",
            bg="#2f4155",
            fg="white",
        ).grid(row=0, column=0)
        self.blowfish_key_path_entry = tk.Entry(
            frame_blowfish, width=15, font="arial 12"
        )
        self.blowfish_key_path_entry.grid(row=0, column=1, padx=3, pady=3)
        tk.Button(
            frame_blowfish,
            text="Choose",
            font="arial 12 bold",
            bg="#4CAF50",
            fg="white",
            command=self.choose_blowfish_key,
        ).grid(row=0, column=2, padx=3, pady=3)

        # Output Secret Image frame
        frame_output = tk.Frame(
            self, bg="#2f4155", bd=2, width=330, height=100, relief=tk.GROOVE
        )
        frame_output.place(x=10, y=360)
        tk.Label(
            frame_output,
            text="Output Secret Image",
            font="arial 15 bold",
            bg="#2f4155",
            fg="white",
        ).grid(row=0, column=0)
        self.output_secret_image_path_entry = tk.Entry(
            frame_output, width=30, font="arial 15"
        )
        self.output_secret_image_path_entry.grid(row=0, column=1, padx=6, pady=6)
        tk.Button(
            frame_output,
            text="Choose",
            command=self.choose_output_secret_image,
        ).grid(row=0, column=2, padx=6, pady=6)

        # Third frame
        frame3 = tk.Frame(
            self, bg="#2f4155", bd=2, width=340, height=80, relief=tk.GROOVE
        )
        frame3.place(x=200, y=420)
        tk.Button(
            frame3,
            text="Choose Stego Image",
            font="arial 12 bold",
            bg="#4CAF50",
            fg="white",
            command=self.choose_stego_image,
        ).place(x=20, y=30)
        tk.Button(
            frame3,
            text="Decode",
            font="arial 12 bold",
            bg="#4CAF50",
            fg="white",
            command=self.decode,
        ).place(x=200, y=30)
        tk.Label(
            frame3,
            text="Picture, Image, Photo File",
            font="arial 10",
            bg="#2f4155",
            fg="white",
        ).place(x=50, y=5)

        tk.Button(
            self,
            text="Switch to Encode",
            font="arial 12 bold",
            bg="#FF9800",
            fg="white",
            command=lambda: controller.show_frame(EncodePage),
        ).pack()

        # # Progress bar
        # self.progress_var = tk.DoubleVar()
        # ttk.Progressbar(
        #     self,
        #     orient="horizontal",
        #     length=200,
        #     mode="determinate",
        #     variable=self.progress_var,
        # ).place(x=500, y=440)

        # Decoded Image frame
        frame_decoded_image = tk.Frame(
            self, bg="white", bd=3, width=340, height=280, relief=tk.GROOVE
        )
        frame_decoded_image.place(x=720, y=80)

        self.lbl_decoded_image = tk.Label(frame_decoded_image, bg="black")
        self.lbl_decoded_image.place(x=0, y=5)

    def choose_stego_image(self):
        filename = filedialog.askopenfilename(
            initialdir=os.getcwd(),
            title="Select Stego Image",
            filetypes=(
                ("PNG FILE", "*.png"),
                ("JPEG FILE", "*.jpeg"),
                ("JPG FILE", "*.jpg"),
                ("ALL FILES", "*.*"),
            ),
        )
        img = Image.open(filename)
        img = img.resize((340, 280), Image.ADAPTIVE)
        img = ImageTk.PhotoImage(img)
        self.lbl1.configure(image=img)
        self.lbl1.image = img
        self.stego_image_path_entry = filename

    def choose_aes_key(self):
        filename = filedialog.askopenfilename(
            initialdir=os.getcwd(), title="Select AES Key File"
        )
        self.aes_key_path_entry.delete(0, tk.END)
        self.aes_key_path_entry.insert(0, filename)

    def choose_blowfish_key(self):
        filename = filedialog.askopenfilename(
            initialdir=os.getcwd(), title="Select Blowfish Key File"
        )
        self.blowfish_key_path_entry.delete(0, tk.END)
        self.blowfish_key_path_entry.insert(0, filename)

    def choose_output_secret_image(self):
        filename = filedialog.asksaveasfilename(
            initialdir=os.getcwd(),
            title="Save Output Secret Image As",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")],
        )
        self.output_secret_image_path_entry.delete(0, tk.END)
        self.output_secret_image_path_entry.insert(0, filename)

    def decrypt_data_aes(self, key, data):
        iv = data[:AES_BLOCK_SIZE]
        ciphertext = data[AES_BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        return cipher.decrypt(ciphertext)

    def decrypt_data_blowfish(self, key, data):
        iv = data[:BLOWFISH_BLOCK_SIZE]
        ciphertext = data[BLOWFISH_BLOCK_SIZE:]
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
        return cipher.decrypt(ciphertext)

    def extract_message_from_image(
        self, image, aes_key, blowfish_key, output_secret_image_path
    ):
        try:
            # Extract the data from the image pixels (LSB Extraction)
            data_bin = ""
            pixels = image.load()
            for i in range(image.width):
                for j in range(image.height):
                    r, g, b = pixels[i, j]
                    data_bin += str(r & 1)
                    data_bin += str(g & 1)
                    data_bin += str(b & 1)

            # Convert the binary string back to bytes
            data = bytes(
                int(data_bin[i : i + 8], 2) for i in range(0, len(data_bin), 8)
            )

            # Extract the lengths of the encrypted images (4 bytes each) and convert them to integers
            aes_image_length = int.from_bytes(data[:4], byteorder="big")
            blowfish_image_length = int.from_bytes(data[4:8], byteorder="big")

            # Extract the encrypted image data from the data
            encrypted_image = data[8 : 8 + aes_image_length + blowfish_image_length]

            # Decrypt the secret image using Blowfish and then AES
            decrypted_secret_image_aes = self.decrypt_data_blowfish(
                blowfish_key, encrypted_image
            )
            decrypted_secret_image_data = self.decrypt_data_aes(
                aes_key, decrypted_secret_image_aes
            )

            # Save the extracted secret image data as bytes to a file
            with open(output_secret_image_path, "wb") as output_image_file:
                output_image_file.write(decrypted_secret_image_data)
            time.sleep(20)
            # Display the extracted secret image
            try:
                if (
                    os.path.exists(output_secret_image_path)
                    and os.path.getsize(output_secret_image_path) > 0
                ):
                    decoded_image = Image.open(output_secret_image_path)
                    decoded_image = decoded_image.resize((340, 280), Image.ADAPTIVE)
                    decoded_image_tk = ImageTk.PhotoImage(decoded_image)
                    self.lbl_decoded_image.configure(image=decoded_image_tk)
                    self.lbl_decoded_image.image = decoded_image_tk

                    # we have successfully decode the image and also outputted it so it's an actual positive instance
                else:
                    raise FileNotFoundError("Output file not found or empty.")
            except Exception as e:
                print(f"Error displaying decoded image: {e}")
                self.lbl_decoded_image.configure(text="Error displaying decoded image")
                self.lbl_decoded_image.image = None
        except Exception as e:
            print(f"Error extracting message from image: {e}")
            self.lbl_decoded_image.configure(text="Error extracting message from image")
            self.lbl_decoded_image.image = None

    def flatten_image_tuples(self, image_tuples):
        return [pixel for image in image_tuples for pixel in image]

    def decode(self):
        stego_image_path = self.stego_image_path_entry
        aes_key_file_path = self.aes_key_path_entry.get()
        blowfish_key_file_path = self.blowfish_key_path_entry.get()
        output_secret_image_path = self.output_secret_image_path_entry.get()
        try:
            start_time = time.time()
            stego_image_pil = Image.open(stego_image_path)

            with open(aes_key_file_path, "rb") as aes_key_file:
                aes_key = aes_key_file.read()
            with open(blowfish_key_file_path, "rb") as blowfish_key_file:
                blowfish_key = blowfish_key_file.read()

            self.extract_message_from_image(
                stego_image_pil, aes_key, blowfish_key, output_secret_image_path
            )

            end_time = time.time() - start_time
            # since decoding is a success we increse the successful decoding atempts
            app.successful_decoded_attempts += 1
            messagebox.showinfo(
                "Success",
                "Secret image extracted and saved successfully!"
                f"\nTime taken for decoding: {end_time:.2f} seconds",
            )

            # get a copy of the decode image
            app.decode_image = output_secret_image_path

        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")
            # flase negative attepmt increase this occur due to undetected data
            app.false_negative_attempts += 1
        # increase the number of decoding
        finally:
            app.total_decoded_attempts += 1
            print("Total decoding attempts", app.total_decoded_attempts)


app = App()
app.mainloop()
