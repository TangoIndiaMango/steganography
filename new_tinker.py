import time
from tkinter import *
from tkinter import StringVar, OptionMenu, filedialog
from PIL import Image, ImageTk
import time

from src.stego_encrypt import embed_message_in_image




def open_file_dialog(entry):
    filename = filedialog.askopenfilename(initialdir="/", title="Select file")
    entry.delete(0, END)
    entry.insert(0, filename)

def encode_button_clicked(
    window, cover_image_path, secret_image_path, output_stego_image_path, algorithm
):
    
    cover_image = Image.open(cover_image_path).convert("RGB")
    cover_image = ImageTk.PhotoImage(cover_image)

    start_time = time.time()
    try:
        stego_image, key = embed_message_in_image(
            cover_image, secret_image_path, algorithm
        )
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

root = Tk()
root.title("Image Steganography")


cover_image = Entry(root, width=50)
secret_image = Entry(root, width=50)
output_image = Entry(root, width=50)

cover_image_button = Button(root, text="Cover Image", command=lambda: open_file_dialog(cover_image))

secret_image_button = Button(root, text="Secret Image", command=lambda: open_file_dialog(secret_image))

output_image_button = Button(root, text="Output Image", command=lambda: open_file_dialog(output_image))

algorithm_label = Label(root, text="Choose Algorithm:")
algorithm_var = StringVar()
algorithm_menu = OptionMenu(root, algorithm_var, "AES", "Blowfish")



encode_button = Button(root, text="Encode", command=lambda: encode_button_clicked(
            root,
            cover_image.get(),
            secret_image.get(),
            output_image.get(),
            algorithm_var.get(),
        ),)

decode_button = Button(root, text="Decode")

cover_image.grid(row=0, column=0, padx=10, pady=10)
cover_image_button.grid(row=0, column=1, padx=10, pady=10)

secret_image.grid(row=1, column=0, padx=10, pady=10)
secret_image_button.grid(row=1, column=1, padx=10, pady=10)

output_image.grid(row=2, column=0, padx=10, pady=10)
output_image_button.grid(row=2, column=1, padx=10, pady=10)

algorithm_label.grid(row=3, column=0, columnspan=2)
algorithm_menu.grid(row=4, column=0, columnspan=2, pady=10)

encode_button.grid(row=5, column=0, columnspan=2, pady=10)
decode_button.grid(row=6, column=0, columnspan=2, pady=10)

root.mainloop()

if __name__ == "__main__":
    root.mainloop()


