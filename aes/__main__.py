"""Command-line interface: python -m aes --mode cbc --key HEX --iv HEX ...

Examples:
  Encrypt text with CBC:
    python -m aes --mode cbc --key 2b7e151628aed2a6abf7158809cf4f3c \\
        --iv 000102030405060708090a0b0c0d0e0f --encrypt "hello aes"

  Decrypt the hex back to text:
    python -m aes --mode cbc --key 2b7e151628aed2a6abf7158809cf4f3c \\
        --iv 000102030405060708090a0b0c0d0e0f --decrypt <hex>

  ECB needs no IV:
    python -m aes --mode ecb --key 2b7e151628aed2a6abf7158809cf4f3c --encrypt "hello aes"
"""

import argparse
from .modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt


def _parse_args(argv=None):
    """Define and parse the CLI flags (kept tiny on purpose)."""
    p = argparse.ArgumentParser(description="From-scratch AES (ECB/CBC).")
    p.add_argument("--mode", choices=("ecb", "cbc"), required=True,
                   help="block mode to use")
    p.add_argument("--key", required=True,
                   help="key as hex (32 hex chars = AES-128, 64 = AES-256)")
    p.add_argument("--iv", default=None,
                   help="IV as 32 hex chars (required for CBC)")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", default=None,
                       help="plaintext string to encrypt (prints hex)")
    group.add_argument("--decrypt", default=None,
                       help="hex ciphertext to decrypt (prints text)")
    return p.parse_args(argv)


def main(argv=None):
    """Entry point: parse flags, run the mode, print the result."""
    args = _parse_args(argv)
    key = bytes.fromhex(args.key)  # ValueError if not valid hex
    if len(key) not in (16, 32):
        raise SystemExit("key must be 16 or 32 bytes (32 or 64 hex chars)")

    if args.mode == "ecb":
        if args.encrypt is not None:
            print(ecb_encrypt(key, args.encrypt.encode()).hex())
        else:
            pt = ecb_decrypt(key, bytes.fromhex(args.decrypt))
            print(pt.decode(errors="replace"))
    else:  # cbc
        if args.iv is None:
            raise SystemExit("CBC needs --iv (32 hex chars)")
        iv = bytes.fromhex(args.iv)
        if len(iv) != 16:
            raise SystemExit("IV must be 16 bytes (32 hex chars)")
        if args.encrypt is not None:
            print(cbc_encrypt(key, iv, args.encrypt.encode()).hex())
        else:
            pt = cbc_decrypt(key, iv, bytes.fromhex(args.decrypt))
            print(pt.decode(errors="replace"))


if __name__ == "__main__":
    main()
