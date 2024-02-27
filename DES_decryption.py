from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

def binary_to_text(binary_str):
    text = ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
    return text

def decrypt_des_ecb(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text

def generate_round_keys(key):
    pc1 = [56, 48, 40, 32, 24, 16, 8,
           0, 57, 49, 41, 33, 25, 17,
           9, 1, 58, 50, 42, 34, 26,
           18, 10, 2, 59, 51, 43, 35,
           62, 54, 46, 38, 30, 22, 14,
           6, 61, 53, 45, 37, 29, 21,
           13, 5, 60, 52, 44, 36, 28,
           20, 12, 4, 27, 19, 11, 3]

    pc2 = [13, 16, 10, 23, 0, 4,
           2, 27, 14, 5, 20, 9,
           22, 18, 11, 3, 25, 7,
           15, 6, 26, 19, 12, 1,
           40, 51, 30, 36, 46, 54,
           29, 39, 50, 44, 32, 47,
           43, 48, 38, 55, 33, 52,
           45, 41, 49, 35, 28, 31]

    # Ensure the key is 64 bits long
    key = key.ljust(64, '0')[:64]

    # Permutation Choice 1
    key_permuted = [key[pc1[i]] for i in range(56)]

    round_keys = []
    for i in range(16):
        if i in [0, 1, 8, 15]:
            key_permuted = key_permuted[1:] + key_permuted[:1]
        else:
            key_permuted = key_permuted[2:] + key_permuted[:2]
        round_key = ''.join([key_permuted[pc2[j]] for j in range(48)])
        round_keys.append(round_key)

    return round_keys

def main():
    binary_ciphertext = "1100101011101101101000100110010101011111101101110011100001110011"
    binary_key = "0100110001001111010101100100010101000011010100110100111001000100"

    ciphertext_bytes = bytes(int(binary_ciphertext[i:i+8], 2) for i in range(0, len(binary_ciphertext), 8))
    key_bytes = bytes(int(binary_key[i:i+8], 2) for i in range(0,len(binary_key), 8))

    round_keys = generate_round_keys(binary_key)

    print("Generated Round Keys:")
    for i, key in enumerate(round_keys, 1):
        print(f"Round {i}: {key}")

    cipher = DES.new(key_bytes, DES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(ciphertext_bytes)

    decrypted_text = decrypted_bytes.decode('utf-8')

    print("\nDecrypted Message:", decrypted_text)

if __name__ == "__main__":
    main()