"""Attack 1: ECB leaks patterns (the classic 'ECB penguin').

A 128x128 RGB picture has huge flat areas (sky, ground): thousands of
identical 16-byte pixel blocks. ECB encrypts equal blocks to equal
ciphertext, so the shape survives encryption and stays visible. CBC chains
blocks, so every block looks random and the picture dissolves into noise.

Method: encrypt the RAW pixel bytes (no PNG header, exactly 128*128*3 =
49152 bytes = 3072 blocks) with our own aes.modes, then draw the
ciphertext bytes back as pixels of the same size. Our modes append one
PKCS#7 padding block, which is simply dropped for the picture.

Run:  python3 -m attacks.ecb_image_leak
Saves: results/img_original.png, results/img_ecb.png, results/img_cbc.png,
       results/img_comparison.png (side-by-side via matplotlib).
Pillow and matplotlib are allowed for this demo only.
"""

import matplotlib

matplotlib.use("Agg")  # headless: write files, never open a window
import matplotlib.pyplot as plt
from PIL import Image, ImageDraw

from aes.modes import ecb_encrypt, cbc_encrypt

IMAGE_W, IMAGE_H = 128, 128  # fixed demo size (128*128*3 = 49152 bytes)
KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
KEY256 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f")
FIXED_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def make_drone_image():
    """Draw a synthetic 128x128 scene: quadcopter silhouette over flat sky.

    Everything is generated with Pillow (no downloads): a flat sky, a
    flat ground strip, a sun disc, and a dark quadcopter (body, 4 arms,
    4 motor pods, 4 rotor discs, 2 skids). Flat fills mean most 16-byte
    pixel blocks repeat — exactly what makes ECB fail visibly.
    """
    sky = (135, 206, 235)     # flat light blue
    ground = (34, 139, 34)     # flat green
    sun = (255, 215, 0)        # flat gold
    body = (30, 30, 30)        # near-black drone
    img = Image.new("RGB", (IMAGE_W, IMAGE_H), sky)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 100, 128, 128], fill=ground)  # ground strip
    draw.ellipse([100, 8, 120, 28], fill=sun)        # sun disc
    cx, cy = 64, 58  # drone centre
    for dx, dy in ((-28, -18), (28, -18), (-28, 18), (28, 18)):
        draw.line([cx, cy, cx + dx, cy + dy], fill=body, width=3)  # arms
        draw.ellipse([cx + dx - 7, cy + dy - 3, cx + dx + 7, cy + dy + 3],
                     fill=body)                                   # rotor disc
        draw.ellipse([cx + dx - 3, cy + dy - 3, cx + dx + 3, cy + dy + 3],
                     fill=(90, 90, 90))                           # motor pod
    draw.rectangle([cx - 12, cy - 7, cx + 12, cy + 7], fill=body)  # body
    draw.line([cx - 8, cy + 7, cx - 8, cy + 20], fill=body, width=2)  # skids
    draw.line([cx + 8, cy + 7, cx + 8, cy + 20], fill=body, width=2)
    draw.line([cx - 12, cy + 20, cx + 12, cy + 20], fill=body, width=2)
    return img


def distinct_blocks(data):
    """Count how many DIFFERENT 16-byte blocks a byte string holds."""
    data = bytes(data)
    return len({data[i:i + 16] for i in range(0, len(data), 16)})


def pixels_from_ciphertext(ciphertext):
    """Take the first 128*128*3 ciphertext bytes (drop the padding block)."""
    return bytes(ciphertext[:IMAGE_W * IMAGE_H * 3])


def run_image_leak():
    """Encrypt the pixels under ECB-128/256 and CBC-128/256; return stats.

    Returns (original_img, ecb_img, cbc_img, stats) where stats maps each
    label to its distinct-16-byte-block count. The PNG files use the
    AES-128 pair; the AES-256 pair is computed too, to prove a longer key
    does not fix a broken mode (used by attacks/summary.py).
    """
    original = make_drone_image()
    pixels = original.tobytes()  # 49152 raw RGB bytes, no header
    stats = {"plain": distinct_blocks(pixels)}
    # ECB pair: equal pixel blocks give equal ciphertext blocks.
    ct = ecb_encrypt(KEY128, pixels)  # our own AES, PKCS#7 adds 1 block
    stats["ecb128"] = distinct_blocks(ct)
    ecb_img = Image.frombytes("RGB", (IMAGE_W, IMAGE_H),
                              pixels_from_ciphertext(ct))
    ct = ecb_encrypt(KEY256, pixels)
    stats["ecb256"] = distinct_blocks(ct)
    # CBC pair: chaining randomises every block (fixed IV keeps it repeatable).
    ct = cbc_encrypt(KEY128, FIXED_IV, pixels)
    stats["cbc128"] = distinct_blocks(ct)
    cbc_img = Image.frombytes("RGB", (IMAGE_W, IMAGE_H),
                              pixels_from_ciphertext(ct))
    ct = cbc_encrypt(KEY256, FIXED_IV, pixels)
    stats["cbc256"] = distinct_blocks(ct)
    return original, ecb_img, cbc_img, stats


def save_results(original, ecb_img, cbc_img):
    """Write the four PNG files (called by main() and attacks/summary.py)."""
    original.save("results/img_original.png")
    ecb_img.save("results/img_ecb.png")
    cbc_img.save("results/img_cbc.png")
    fig, axes = plt.subplots(1, 3, figsize=(9, 3))
    for ax, img, title in ((axes[0], original, "Original"),
                           (axes[1], ecb_img, "ECB-128 (shape leaks!)"),
                           (axes[2], cbc_img, "CBC-128 (noise)")):
        ax.imshow(img)
        ax.set_title(title)
        ax.axis("off")
    fig.tight_layout()
    fig.savefig("results/img_comparison.png")


def main():
    """Generate the scene, encrypt it, save all four PNG files, print stats."""
    original, ecb_img, cbc_img, stats = run_image_leak()
    save_results(original, ecb_img, cbc_img)
    print("Distinct 16-byte blocks (fewer = more pattern leaked):")
    for label in ("plain", "ecb128", "ecb256", "cbc128", "cbc256"):
        print("  %-7s: %d" % (label, stats[label]))
    print("ECB keeps ~plaintext count -> silhouette visible.")
    print("CBC is ~every block unique -> noise. Longer key changes nothing.")


if __name__ == "__main__":
    main()
