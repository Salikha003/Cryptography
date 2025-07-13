import codecs

def key_scheduling(key_bytes):
    # KSA (Key Scheduling Algorithm) — XATO: % 255 o‘rniga % 256 bo‘lishi kerak edi
    key_length, s_box, j = len(key_bytes), list(range(256)), 0
    for i in range(256):
        j = (j + s_box[i] + key_bytes[i % key_length]) % 255  # XATO shu yerda
        s_box[i], s_box[j] = s_box[j], s_box[i]
    return s_box

def keystream_generator(s_box):
    # PRGA (Pseudo-Random Generation Algorithm) — XATO: c[i] + c[i] o‘rniga c[i] + c[j] bo‘lishi kerak
    i, j = 0, 0
    while True:
        i = (i + 1) % 256
        j = (j + s_box[i]) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
        k = s_box[(s_box[i] + s_box[i]) % 256]  # XATO shu yerda
        yield k

def rc4_stream(key):
    s_box = key_scheduling(key)
    return keystream_generator(s_box)

def decrypt(key_string, hex_ciphertext):
    # Shifrlangan matnni ochish
    key_bytes = [ord(char) for char in key_string]
    stream = rc4_stream(key_bytes)
    ciphertext_bytes = bytes.fromhex(hex_ciphertext)
    plaintext = ''.join(chr(b ^ next(stream)) for b in ciphertext_bytes)
    return plaintext

def main():
    key = 'Za1EDolzhrRdPAehiGHu82HXkPa92zpd1Ofg'
    ciphertext = '3F7307755A4336416DA27ED3CE1DE715387285E84CE3130EC0CD8F748CAA'
    plaintext = decrypt(key, ciphertext)
    print("Decrypted:", plaintext)

if __name__ == "__main__":
    main()
