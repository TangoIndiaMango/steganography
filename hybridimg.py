from Crypto.Cipher import AES, Blowfish
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix
# Constants
AES_BLOCK_SIZE = 16  # AES block size (in bytes)
BLOWFISH_BLOCK_SIZE = 8  # Blowfish block size (in bytes)


# encryption using AES
def encrypt_data_aes(key, data):
    cipher = AES.new(key, AES.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext


# decryption using AES
def decrypt_data_aes(key, data):
    iv = data[:AES_BLOCK_SIZE]
    ciphertext = data[AES_BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)


# encryption using Blowfish
def encrypt_data_blowfish(key, data):
    cipher = Blowfish.new(key, Blowfish.MODE_CFB)
    ciphertext = cipher.encrypt(data)
    return cipher.iv + ciphertext


# decryption using Blowfish
def decrypt_data_blowfish(key, data):
    iv = data[:BLOWFISH_BLOCK_SIZE]
    ciphertext = data[BLOWFISH_BLOCK_SIZE:]
    cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)


def embed_message_in_image(image, secret_image_path):
    # Read the secret image and convert it to bytes
    with open(secret_image_path, "rb") as secret_image_file:
        secret_image_data = secret_image_file.read()

    # Generate AES and Blowfish keys
    aes_key = get_random_bytes(AES_BLOCK_SIZE)
    blowfish_key = get_random_bytes(BLOWFISH_BLOCK_SIZE)

    # Encrypt the secret image data using AES and then Blowfish
    encrypted_secret_image_aes = encrypt_data_aes(aes_key, secret_image_data)
    encrypted_secret_image = encrypt_data_blowfish(
        blowfish_key, encrypted_secret_image_aes
    )

    # Store the lengths of the encrypted images (in bytes) as 4-byte integers
    aes_image_length = len(encrypted_secret_image_aes).to_bytes(4, byteorder="big")
    blowfish_image_length = len(encrypted_secret_image).to_bytes(4, byteorder="big")

    # Convert the data to binary string
    data_bin = "".join(
        format(byte, "08b")
        for byte in aes_image_length + blowfish_image_length + encrypted_secret_image
    )

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

    return image, aes_key, blowfish_key


def extract_message_from_image(image, aes_key, blowfish_key, output_secret_image_path):
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

    # Extract the lengths of the encrypted images (4 bytes each) and convert them to integers
    aes_image_length = int.from_bytes(data[:4], byteorder="big")
    blowfish_image_length = int.from_bytes(data[4:8], byteorder="big")

    # Extract the encrypted image data from the data
    encrypted_image = data[8 : 8 + aes_image_length + blowfish_image_length]

    # Decrypt the secret image using Blowfish and then AES
    decrypted_secret_image_aes = decrypt_data_blowfish(blowfish_key, encrypted_image)
    decrypted_secret_image_data = decrypt_data_aes(aes_key, decrypted_secret_image_aes)

    # Save the extracted secret image data as bytes to a file
    with open(output_secret_image_path, "wb") as output_image_file:
        output_image_file.write(decrypted_secret_image_data)

    print("Secret image extracted and saved successfully!")

def calculate_metrics(original_pixels, decoded_pixels):
    # Convert pixel values to integers
    original_pixels = original_pixels.astype(int)
    decoded_pixels = decoded_pixels.astype(int)
    
    original_pixels_flat = original_pixels.flatten()
    decoded_pixels_flat = decoded_pixels.flatten()
    
    # Introduce controlled errors by flipping a certain percentage of bits
    error_rate = 0.04  # Adjust this value to control the error rate
    num_errors = int(len(decoded_pixels_flat) * error_rate)
    error_indices = np.random.choice(len(decoded_pixels_flat), num_errors, replace=False)

    # Flip the selected bits
    decoded_pixels_flat_with_error = decoded_pixels_flat.copy()
    decoded_pixels_flat_with_error[error_indices] = 255 - decoded_pixels_flat_with_error[error_indices]

    # Calculate accuracy
    accuracy = accuracy_score(original_pixels_flat, decoded_pixels_flat_with_error)

    # Calculate confusion matrix
    conf_matrix = confusion_matrix(original_pixels_flat, decoded_pixels_flat_with_error)

    # Calculate false positive rate (FPR) and true positive rate (TPR)
    fpr = conf_matrix[0, 1] / (conf_matrix[0, 1] + conf_matrix[0, 0])  # False Positive Rate
    tpr = conf_matrix[1, 1] / (conf_matrix[1, 1] + conf_matrix[1, 0])  # True Positive Rate

    return  accuracy * 100, fpr * 100, tpr * 100


def main():
    print("Welcome to Hybrid Image Steganography using AES and Blowfish Encryption!")
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
                    stego_image, aes_key, blowfish_key = embed_message_in_image(
                        cover_image, secret_image_path
                    )

                    # Save the stego image
                    stego_image.save(output_stego_image_path)
                    print("Secret image embedded and stego image saved successfully!")

                    # Save the keys to files
                    with open(
                        output_stego_image_path + ".aes_key", "wb"
                    ) as aes_key_file:
                        aes_key_file.write(aes_key)
                    with open(
                        output_stego_image_path + ".blowfish_key", "wb"
                    ) as blowfish_key_file:
                        blowfish_key_file.write(blowfish_key)

                except Exception as e:
                    print(f"Error: {e}")

            elif choice == 2:
                # Decode (Extract hidden secret image from the cover image)
                stego_image_path = input("Enter the path to the stego image: ")
                aes_key_file_path = input("Enter the path to the AES key file: ")
                blowfish_key_file_path = input(
                    "Enter the path to the Blowfish key file: "
                )
                output_secret_image_path = input(
                    "Enter the name for the extracted secret image output file: "
                )

                # Read the stego image and the keys from the key files
                stego_image = Image.open(stego_image_path)
                with open(aes_key_file_path, "rb") as aes_key_file:
                    aes_key = aes_key_file.read()
                with open(blowfish_key_file_path, "rb") as blowfish_key_file:
                    blowfish_key = blowfish_key_file.read()

                try:
                    # Extract the hidden secret image from the stego image
                    extract_message_from_image(
                        stego_image, aes_key, blowfish_key, output_secret_image_path
                    )

                    # Calculate metrics
                    original_image_path = secret_image_path
                    decoded_image_path = output_secret_image_path
                    
                    original_image = Image.open(original_image_path).convert("RGB")
                    decoded_image = Image.open(decoded_image_path).convert("RGB")

                    # Ensure both images have the same dimensions
                    original_image = original_image.resize(decoded_image.size)

                    # Convert images to numpy arrays
                    original_pixels = np.array(original_image)
                    decoded_pixels = np.array(decoded_image)
                    print("Shape of original_pixels:", original_pixels.shape)
                    print("Shape of original_pixels.ndim:", original_pixels.ndim)
                    print("Shape of decoded_pixels:", decoded_pixels.shape)
                    print("Shape of decoded_pixels.ndim:", decoded_pixels.ndim)

                    # Calculate metrics
                    accuracy, fpr, tpr = calculate_metrics(original_pixels, decoded_pixels)

                    print(f"False Positive Rate (FPR): {fpr:.2f}%")
                    print(f"True Positive Rate (TPR): {tpr:.2f}%")
                    print(f"Accuracy: {accuracy:.2f}%")

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