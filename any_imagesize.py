from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import os

# Constants
BLOCK_SIZE = 16  # AES block size (in bytes)


def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext


def decrypt_data(key, data):
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)


def embed_message_in_image(image, secret_image_path):
    # Read the secret image and convert it to bytes
    with open(secret_image_path, "rb") as secret_image_file:
        secret_image_data = secret_image_file.read()

    # Generate AES key
    key = get_random_bytes(BLOCK_SIZE)

    # Encrypt the secret image data
    encrypted_secret_image = encrypt_data(key, secret_image_data)

    # Store the length of the encrypted image (in bytes) as a 4-byte integer
    image_length = len(encrypted_secret_image).to_bytes(4, byteorder="big")

    # Convert the data to binary string
    data_bin = "".join(format(byte, "08b") for byte in image_length + encrypted_secret_image)

    # Embed the data into the image pixels (LSB Embedding)
    pixels = image.load()
    pixel_index = 0
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = pixels[i, j]

            # Embed one bit of the data in each pixel's least significant bit (R, G, and B channels)
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


def extract_message_from_image(image, key, output_secret_image_path):
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
    data = bytes(int(data_bin[i : i + 8], 2) for i in range(0, len(data_bin), 8))

    # Extract the length of the encrypted image (4 bytes) and convert it to an integer
    image_length = int.from_bytes(data[:4], byteorder="big")

    # Extract the encrypted image data from the data
    encrypted_image = data[4 : 4 + image_length]

    # Decrypt the secret image
    decrypted_secret_image_data = decrypt_data(key, encrypted_image)

    # Save the extracted secret image data as bytes to a file
    with open(output_secret_image_path, "wb") as output_image_file:
        output_image_file.write(decrypted_secret_image_data)

    print("Secret image extracted and saved successfully!")


def main():
    print("Welcome to Image Steganography using AES Encryption!")
    try:
        while True:
            print("\n1. Encode (Embed secret image in the cover image)")
            print("2. Decode (Extract hidden secret image from the cover image)")
            print("3. Exit")
            choice = int(input("Please enter your choice (1, 2, or 3): "))

            if choice == 1:
                # Encode (Embed secret image in the cover image)
                cover_image_path = input("Enter the path to the cover image: ")
                secret_image_path = input("Enter the path to the secret image: ")
                output_stego_image_path = input(
                    "Enter the name for the stego image output file: "
                )

                # Read the cover image and convert it to RGB mode
                cover_image = Image.open(cover_image_path).convert("RGB")

                try:
                    # Embed the secret image in the cover image
                    stego_image, key = embed_message_in_image(
                        cover_image, secret_image_path
                    )

                    # Save the stego image
                    stego_image.save(output_stego_image_path)
                    print("Secret image embedded and stego image saved successfully!")

                    # Save the key to a file
                    with open(output_stego_image_path + ".key", "wb") as key_file:
                        key_file.write(key)
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == 2:
                # Decode (Extract hidden secret image from the cover image)
                stego_image_path = input("Enter the path to the stego image: ")
                key_file_path = input("Enter the path to the key file: ")
                output_secret_image_path = input(
                    "Enter the name for the extracted secret image output file: "
                )

                # Read the stego image and the AES key from the key file
                stego_image = Image.open(stego_image_path)
                with open(key_file_path, "rb") as key_file:
                    key = key_file.read()

                try:
                    # Extract the hidden secret image from the stego image
                    extract_message_from_image(
                        stego_image, key, output_secret_image_path
                    )
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == 3:
                break

            else:
                print("Invalid choice. Please enter 1, 2, or 3.")

    except ValueError as ve:
        print(f"Error: {ve}")
    except KeyboardInterrupt:
        print("\nOperation canceled by the user.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
