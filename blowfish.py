from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from PIL import Image
import os

# Constants
BLOCK_SIZE = 8  # Blowfish block size (in bytes)


def encrypt_data_blowfish(key, data):
    cipher = Blowfish.new(key, Blowfish.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext


def decrypt_data_blowfish(key, data):
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)


def embed_message_in_image(image, message):
    # Convert the message to bytes
    message_bytes = message.encode("utf-8")

    # Generate Blowfish key
    key = get_random_bytes(BLOCK_SIZE)

    # Encrypt the message
    encrypted_message = encrypt_data_blowfish(key, message_bytes)

    # Store the length of the encrypted message (in bytes) as a 4-byte integer
    message_length = len(encrypted_message).to_bytes(4, byteorder="big")

    # Combine the message length and the encrypted message
    data_to_embed = message_length + encrypted_message

    # Convert the data to binary string
    data_bin = "".join(format(byte, "08b") for byte in data_to_embed)

    # Ensure the data will fit into the image
    max_data_length = (image.width * image.height * 3) // 8
    if len(data_bin) > max_data_length:
        raise ValueError(
            f"Data is too long to fit into the image. Max length: {max_data_length}"
        )

    # Embed the data into the image pixels
    pixels = image.load()
    pixel_index = 0
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = pixels[i, j]

            # Embed one bit of the data in each pixel's least significant bit
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


def extract_message_from_image(image, key):
    # Extract the data from the image pixels
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

    # Extract the length of the encrypted message (4 bytes) and convert it to an integer
    message_length = int.from_bytes(data[:4], byteorder="big")

    # Extract the encrypted message from the data
    encrypted_message = data[4 : 4 + message_length]

    # Decrypt the message
    decrypted_message = decrypt_data_blowfish(key, encrypted_message)

    return decrypted_message


def main():
    print("Welcome to Image Steganography using Blowfish Encryption!")
    try:
        while True:
            print("\n1. Encode (Embed message in the image)")
            print("2. Decode (Extract hidden message from the image)")
            print("3. Exit")
            choice = int(input("Please enter your choice (1, 2, or 3): "))

            if choice == 1:
                # Encode (Embed message in the image)
                image_path = input("Enter the path to the cover image: ")
                message = input("Enter the message to hide: ")
                output_stego_image_path = input(
                    "Enter the name for the stego image output file: "
                )

                # Read the image and convert it to RGB mode
                image = Image.open(image_path).convert("RGB")

                try:
                    # Embed the message in the image
                    stego_image, key = embed_message_in_image(image, message)

                    # Save the stego image
                    stego_image.save(output_stego_image_path)
                    print("Message embedded and image saved successfully!")

                    # Save the key to a file
                    with open(output_stego_image_path + ".key", "wb") as key_file:
                        key_file.write(key)
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == 2:
                # Decode (Extract hidden message from the image)
                stego_image_path = input("Enter the path to the stego image: ")
                key_file_path = input("Enter the path to the key file: ")

                # Read the stego image and the Blowfish key from the key file
                stego_image = Image.open(stego_image_path)
                with open(key_file_path, "rb") as key_file:
                    key = key_file.read()

                try:
                    # Extract the hidden message from the stego image
                    hidden_message_bytes = extract_message_from_image(stego_image, key)

                    # Save the extracted message as bytes to a file
                    output_message_file_path = input(
                        "Enter the name for the extracted message output file: "
                    )
                    with open(output_message_file_path, "wb") as output_file:
                        output_file.write(hidden_message_bytes)
                    print("Hidden message extracted and saved successfully!")
                    print(hidden_message_bytes.decode("utf-8"))
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
