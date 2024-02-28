# Sofia Dillhoff
# 2/27/24
# Computer Security HW 2 - DES decryption algorithm

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

def f_function(Rn, round_key):
    # Expansion permutation
    expansion_permutation = [
        31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10,
        11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19,
        20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27,
        28, 29, 30, 31, 0
    ]

    # Apply expansion permutation
    exp_Rn = [Rn[expansion_permutation[i]] for i in range(48)]

    # XOR with round key
    xor_result = ''.join(str(int(exp_Rn[i]) ^ int(round_key[i])) for i in range(48))

    # substitution boxes
    s_boxes = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
 
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
 
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
 
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
 
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
 
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
 
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
 
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]

    substituted_bits = ''
    for i in range(8):
        row = int(xor_result[i * 6] + xor_result[i * 6 + 5], 2)
        col = int(xor_result[i * 6 + 1:i * 6 + 5], 2)
        substituted_bits += format(s_boxes[i][row][col], '04b')

    # permutation box
    permutation_box = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
                        1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

    f_output = ''.join([substituted_bits[permutation_box[i]] for i in range(32)])

    return f_output

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

    decrypt_bin_str = ''.join(format(byte, '08b') for byte in decrypted_bytes)
    
# Print output of f function and LnRn in each iteration
    print("\nOutput of f function and LnRn in each iteration:")
    LnRn = decrypt_bin_str[:32], decrypt_bin_str[32:]
    for i in range(16):
        f_output = f_function(LnRn[1], round_keys[i])  # Replace with actual f function
        print(f"Iteration {i + 1}: f_output={f_output}, LnRn={LnRn}")
        # Update LnRn for the next iteration
        LnRn = LnRn[1], f_output

if __name__ == "__main__":
    main()