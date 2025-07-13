from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from tqdm import tqdm
import binascii
import base64

# --- Part 1: Brute-forcing the key and decrypting the plaintext ---

prefix = b'Super_Secret_'
ciphertext_hex = 'dd95b1d1373f97307b1943a00bd9a09fc9568802187663ff93cadfedd688b644'
ciphertext = bytes.fromhex(ciphertext_hex)

found_key = None
found_plaintext = None

print("Starting brute-force for the AES key...")

for b1 in tqdm(range(256), desc="Brute-forcing key byte 1"):
    for b2 in range(256):
        for b3 in range(256):
            key_candidate = prefix + bytes([b1, b2, b3])
            try:
                cipher = AES.new(key_candidate, AES.MODE_ECB)
                decrypted_bytes = cipher.decrypt(ciphertext)
                pt = unpad(decrypted_bytes, AES.block_size)
                decoded_pt = pt.decode('utf-8')
                if "{" in decoded_pt or "flag" in decoded_pt or "S" in decoded_pt:
                    found_key = key_candidate
                    found_plaintext = decoded_pt
                    print(f"\n[+] FOUND!")
                    print(f"Key: {found_key}")
                    print(f"Plaintext: {found_plaintext}")
                    break
            except Exception:
                continue
        if found_key:
            break
    if found_key:
        break

# --- Part 2: Decrypting a Base64 encoded flag ---
    
def decrypt_base64_flag():
    encoded = b"UzIxeydnb29kX2pvYiExISd9"
    flag = base64.b64decode(encoded).decode()
    return flag.replace("'", "")  # remove ' if any

if __name__ == "__main__":
    print("Flag:", decrypt_base64_flag())


