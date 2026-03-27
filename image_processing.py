import cv2
import numpy as np

def generate_binary_template(img_array):
    # Convert to grayscale
    gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY)

    # Extract features using Canny edge detection
    edges = cv2.Canny(gray, 100, 200)

    # Convert to binary (0/1)
    binary_template = (edges > 0).astype(int)

    # Convert 2D → 1D
    binary_template_1d = binary_template.flatten()

    return binary_template_1d
