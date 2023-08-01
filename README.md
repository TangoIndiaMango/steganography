# steganography
### Using AES and Blowfish to perform steganography for both text and Image

#### Description:
- ###### Note:
- This description is for the image encryption alone [any_imagesize.blowfish.py, any_imagesize.py].
- The steno_image.py has a limitation of image size.
This is a Python script for image steganography that uses AES encryption to embed a secret image into another cover image. 
The hidden secret image can later be extracted from the stego image using the provided key.
#### Requirements:
- Python 3.x
- Pillow (Python Imaging Library)
  
### How to Use:

#### Step 1: Preparation

- Place the image_steganography.py script and the two image files (cover image and secret image) in the same directory.
#### Step 2: Embed Secret Image

- Open a terminal or command prompt in that directory.
#### Run the following command:
```
python image_steganography.py
```
- The script will display a menu with options:
```
1. Encode (Embed secret image in the cover image)
2. Decode (Extract hidden secret image from the cover image)
3. Exit
```
- Choose option 1 to embed the secret image into the cover image.
- Provide the following information:
 ```
Enter the path to the cover image (e.g., cover_image.png).
Enter the path to the secret image (e.g., hide.png).
Enter the name for the stego image output file (e.g., hidden.png).
```
- The script will perform the embedding process and create the stego image hidden.png.
#### Step 3: Extract Hidden Secret Image
- Open a terminal or command prompt in the same directory.
Run the following command:
```
python image_steganography.py
```
- The script will display the menu again. This time, choose option 2.
- Provide the following information:
```
Enter the path to the stego image (e.g., hidden.png).
Enter the path to the key file (e.g., hidden.png.key).
Enter the name for the extracted secret image output file (e.g., hideOutput.png).
```
- The script will perform the extraction process and save the extracted secret image as hideOutput.png.
#### Important Notes:
The cover image and secret image files should be in PNG format for lossless storage of image data.
The encryption key is stored in the key file (e.g., hidden.png.key) and is necessary for extracting the hidden secret image. Please keep the key file secure and do not lose it.
### Note: 
This guide assumes that the provided input file paths are correct, and the images are located in the same directory as the script. 
Make sure to adjust the file paths accordingly if your images are in a different directory.

## Disclaimer: 
Image steganography is a technique used to hide information within images. 
