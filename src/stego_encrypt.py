from Crypto.Cipher import Blowfish, AES
from Crypto.Random import get_random_bytes



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
    print("Hello world")
    # with open(secret_image_path, "rb") as secret_image_file:
    #     secret_image_data = secret_image_file.read()

    # if algorithm == "AES":
    #     key = get_random_bytes(BLOCK_SIZE_AES)
    #     encrypted_secret_image = encrypt_data_aes(key, secret_image_data)
    # elif algorithm == "Blowfish":
    #     key = get_random_bytes(BLOCK_SIZE_BLOWFISH)
    #     encrypted_secret_image = encrypt_data_blowfish(key, secret_image_data)

    # image_length = len(encrypted_secret_image).to_bytes(4, byteorder="big")
    # data_bin = "".join(
    #     format(byte, "08b") for byte in image_length + encrypted_secret_image
    # )

    # pixels = image.load()
    # pixel_index = 0
    # for i in range(image.width):
    #     for j in range(image.height):
    #         r, g, b = pixels[i, j]

    #         if pixel_index < len(data_bin):
    #             r = r & ~1 | int(data_bin[pixel_index])
    #             pixel_index += 1
    #         if pixel_index < len(data_bin):
    #             g = g & ~1 | int(data_bin[pixel_index])
    #             pixel_index += 1
    #         if pixel_index < len(data_bin):
    #             b = b & ~1 | int(data_bin[pixel_index])
    #             pixel_index += 1

    #         pixels[i, j] = (r, g, b)

    # return image, key


def extract_message_from_image(image, key, output_secret_image_path, algorithm):
    data_bin = ""
    pixels = image.load()
    for i in range(image.width):
        for j in range(image.height):
            r, g, b = pixels[i, j]
            data_bin += str(r & 1)
            data_bin += str(g & 1)
            data_bin += str(b & 1)

    data = bytes(int(data_bin[i : i + 8], 2) for i in range(0, len(data_bin), 8))

    image_length = int.from_bytes(data[:4], byteorder="big")
    encrypted_image = data[4 : 4 + image_length]

    if algorithm == "AES":
        decrypted_secret_image_data = decrypt_data_aes(key, encrypted_image)
    elif algorithm == "Blowfish":
        decrypted_secret_image_data = decrypt_data_blowfish(key, encrypted_image)

    with open(output_secret_image_path, "wb") as output_image_file:
        output_image_file.write(decrypted_secret_image_data)

    print("Secret image extracted and saved successfully!")

