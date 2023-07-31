from blowfish import *

# Example usage:
message_to_hide = "This is a secret message!"
image_path = "cover_image.png"
output_stego_image_path = "stego_image.png"


# Read the image and convert it to RGB mode
image = Image.open(image_path).convert('RGB')

# Embed the message in the image
stego_image, key = embed_message_in_image(image, message_to_hide)

# Save the stego image
stego_image.save(output_stego_image_path)

# Save the AES key to a file
with open(output_stego_image_path + ".key", "wb") as key_file:
    key_file.write(key)

# Read the stego image and the AES key
stego_image = Image.open(output_stego_image_path)
with open(output_stego_image_path + ".key", "rb") as key_file:
    key = key_file.read()

# Extract the hidden message from the stego image
hidden_message = extract_message_from_image(stego_image, key)
print("Hidden Message:", hidden_message)
