"""
LSB Embedder — untuk membuat sample gambar dengan pesan tersembunyi.
Digunakan untuk keperluan testing dan demonstrasi.
"""

import numpy as np
from PIL import Image


def embed_message(image_path: str, message: str, output_path: str) -> int:
    """
    Sembunyikan pesan teks ke dalam gambar menggunakan metode LSB.

    Args:
        image_path: Path gambar sumber
        message: Pesan yang akan disembunyikan
        output_path: Path output gambar

    Returns:
        Jumlah bit yang disematkan
    """
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img).flatten().astype(np.uint8)

    # Tambahkan null terminator
    message_bytes = (message + '\x00').encode('utf-8')
    bits_needed = len(message_bytes) * 8

    if bits_needed > len(pixels):
        raise ValueError(
            f"Pesan terlalu panjang! Kapasitas: {len(pixels) // 8} bytes, "
            f"diperlukan: {len(message_bytes)} bytes"
        )

    # Embed bit per bit ke LSB channel R
    bit_idx = 0
    for byte in message_bytes:
        for bit_pos in range(7, -1, -1):
            bit = (byte >> bit_pos) & 1
            pixels[bit_idx] = (pixels[bit_idx] & 0xFE) | bit
            bit_idx += 1

    result = pixels.reshape(np.array(img).shape)
    Image.fromarray(result).save(output_path, 'PNG')
    return bits_needed


def extract_message(image_path: str, max_bytes: int = 1024) -> str:
    """
    Ekstrak pesan tersembunyi dari gambar menggunakan metode LSB.

    Args:
        image_path: Path gambar yang berisi pesan
        max_bytes: Maksimum byte yang dicoba diekstrak

    Returns:
        Pesan yang ditemukan, atau string kosong jika tidak ada
    """
    img = Image.open(image_path).convert('RGB')
    pixels = np.array(img).flatten()

    bits = pixels[:max_bytes * 8] & 1
    chars = []

    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        if byte == 0:
            break
        chars.append(chr(byte))

    return ''.join(chars)
