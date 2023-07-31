import base64
from Crypto.Cipher import AES, Blowfish
from Crypto.Random import get_random_bytes
from PIL import Image

# Constants
BLOCK_SIZE_AES = 16  # AES block size (in bytes)
BLOCK_SIZE_BLOWFISH = 8  # Blowfish block size (in bytes)


def encrypt_data(key, data, encryption_algorithm):
    if encryption_algorithm == "AES":
        cipher = AES.new(key, AES.MODE_CFB)
    elif encryption_algorithm == "Blowfish":
        cipher = Blowfish.new(key, Blowfish.MODE_CFB)
    else:
        raise ValueError("Unsupported encryption algorithm.")
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext


def decrypt_data(key, data, encryption_algorithm):
    if encryption_algorithm == "AES":
        iv = data[:BLOCK_SIZE_AES]
        ciphertext = data[BLOCK_SIZE_AES:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    elif encryption_algorithm == "Blowfish":
        iv = data[:BLOCK_SIZE_BLOWFISH]
        ciphertext = data[BLOCK_SIZE_BLOWFISH:]
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
    else:
        raise ValueError("Unsupported encryption algorithm.")
    return cipher.decrypt(ciphertext)


def embed_message_in_image(image, message, encryption_algorithm):
    # Convert the message to bytes
    message_bytes = message.encode("utf-8")

    # Generate AES and Blowfish keys
    aes_key = get_random_bytes(BLOCK_SIZE_AES)
    blowfish_key = get_random_bytes(BLOCK_SIZE_BLOWFISH)

    # Encrypt the message with AES
    encrypted_message_aes = encrypt_data(aes_key, message_bytes, "AES")

    # Encrypt the AES encrypted message with Blowfish
    encrypted_message = encrypt_data(blowfish_key, encrypted_message_aes, "Blowfish")

    # Combine the encrypted message and algorithm info (1 byte)
    # The first byte will store the length of the encryption algorithm string (max length: 255 characters)
    # The rest of the data will be the encryption algorithm string
    algo_str = encryption_algorithm.encode("utf-8")
    data_to_embed = bytes([len(algo_str)]) + algo_str + encrypted_message

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

    return image, aes_key, blowfish_key


def extract_message_from_image(image, aes_key, blowfish_key):
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

    # Extract the length of the encryption algorithm string (1 byte)
    algo_str_length = data[0]

    # Extract the encrypted message
    encrypted_message = data[1 : 1 + algo_str_length :]

    # Decrypt the Blowfish encrypted message
    decrypted_message_aes = decrypt_data(blowfish_key, encrypted_message, "Blowfish")

    # Decrypt the AES encrypted message
    # decrypted_message = decrypt_data(aes_key, decrypted_message_aes, "AES")

    # Alternatively, you can convert the binary data to base64
    hidden_message_base64 = base64.b64encode(decrypted_message_aes).decode("utf-8")

    return hidden_message_base64



def save_key_to_file(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)


def read_key_from_file(filename):
    with open(filename, "rb") as key_file:
        key = key_file.read()
    return key


def main():
    print("Welcome to Image Steganography using Cascading Encryption (AES + Blowfish)!")
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
                    stego_image, aes_key, blowfish_key = embed_message_in_image(
                        image, message, encryption_algorithm="AES+Blowfish"
                    )

                    # Save the stego image
                    stego_image.save(output_stego_image_path)
                    print("Message embedded and image saved successfully!")

                    # Save the AES and Blowfish keys to files
                    save_key_to_file(aes_key, output_stego_image_path + ".aes.key")
                    save_key_to_file(
                        blowfish_key, output_stego_image_path + ".blowfish.key"
                    )
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == 2:
                # Decode (Extract hidden message from the image)
                stego_image_path = input("Enter the path to the stego image: ")
                aes_key_file_path = input("Enter the path to the AES key file: ")
                blowfish_key_file_path = input(
                    "Enter the path to the Blowfish key file: "
                )

                # Read the stego image and the AES and Blowfish keys
                stego_image = Image.open(stego_image_path)
                aes_key = read_key_from_file(aes_key_file_path)
                blowfish_key = read_key_from_file(blowfish_key_file_path)

                try:
                    # Extract the hidden message from the stego image
                    hidden_message = extract_message_from_image(
                        stego_image, aes_key, blowfish_key
                    )

                    # Print the extracted message
                    print("Hidden Message:", hidden_message)
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
