import random
import struct
from base64 import b64decode
from datetime import datetime, timezone
from Crypto.Cipher import ChaCha20
from tqdm import tqdm


ENCRYPTED_DATA = {
    "key": "ZJLG3ISPIHPLEoSe9dlErrGtOGlxfTO4AJ23y8fvgHQ=",
    "ciphertext": "u1eldjdCfC85wyWiBp8uPOQtRI5LrSZTPk+vdJPhfKd1z00sKl1b5A=="
}

# Funksiya: Base64 formatidan baytlarga o'tkazish 
def decode_base64_data(data):
    return b64decode(data["key"]), b64decode(data["ciphertext"])

# EXACT Instructor nonce generation
def generate_nonce(seed_value):
    random.seed(seed_value)   # Instructorning xatosi shunda edi
    partial_nonce = struct.pack("<Q", random.randint(1, 2**64 - 1))
    full_nonce = b'\x00\x00\x00\x00' + partial_nonce
    return full_nonce

# Funksiya: Flag topishga harakat qilish
def try_decrypt(key_bytes, ciphertext_bytes, nonce):
    cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
    return cipher.decrypt(ciphertext_bytes)

# Asosiy brute-force sikli
def brute_force_decrypt():
    start_time = int(datetime(2022, 1, 1).timestamp())
    end_time = int(datetime(2025, 6, 17).timestamp())

    print(f"[INFO] Starting brute-force between {datetime.fromtimestamp(start_time, tz=timezone.utc)} and {datetime.fromtimestamp(end_time, tz=timezone.utc)}")

    key_bytes, ciphertext_bytes = decode_base64_data(ENCRYPTED_DATA)

# tqdm progress bar bilan yuritamiz
    for seed_time in tqdm(range(start_time, end_time), desc="Brute-forcing timestamps", unit="seed"):
        try:
            nonce = generate_nonce(seed_time)
            decrypted_text = try_decrypt(key_bytes, ciphertext_bytes, nonce)

            if b"flag{" in decrypted_text or b"S21{" in decrypted_text:
                print("\n[SUCCESS] Flag recovered!")
                print("Seed (timestamp):", seed_time)
                print("Nonce (hex):", nonce.hex())
                print("Flag:")
                print(decrypted_text.decode(errors='replace'))

                with open("crack.txt", "w", encoding="utf-8") as output_file:
                    output_file.write(decrypted_text.decode(errors='replace') + "\n")
                    output_file.write("\nInstructor mistake:\n")
                    output_file.write("Used random.seed(int(time.time())) with 8-byte nonce (incorrect for ChaCha20, requires 12 bytes)\n")
                return

        except Exception:
            continue

    print("\n[INFO] Brute-force process finished without finding flag.")

if __name__ == "__main__":
    brute_force_decrypt()
