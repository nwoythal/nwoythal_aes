#!/usr/bin/python3
import argparse
import pdb

mix_col_mat = [[2, 3, 1, 1],
               [1, 2, 3, 1],
               [1, 1, 2, 3],
               [3, 1, 1, 2]]

#           0     1     2     3     4     5     6     7     8     9     A     B     C    D      E     F
sbox = [[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],  # 0
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],  # 1
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],  # 2
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],  # 3
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],  # 4
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],  # 5
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],  # 6
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],  # 7
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],  # 8
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],  # 9
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],  # A
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],  # B
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],  # C
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],  # D
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],  # E
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]  # F

rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8]

debug = 0
key_expansion = 0


def expand_key(key, itr):
    new_mat = [[key[1][3]], [key[2][3]], [key[3][3]], [key[0][3]]]
    sub_col = sub_bytes(new_mat)

    for row in range(len(sub_col)):
        new_mat[row][0] = sub_col[row][0] ^ rcon[itr + 1] ^ key[row][0]  # xor round constant, key, insert into new key

    for col in range(1, len(key)):
        for row in range(len(key)):
            new_mat[row].append(key[row][col] ^ new_mat[row][col - 1])

    if(debug or key_expansion):
        print("NEW KEY FOR ROUND " + str(itr + 1))
        dump_matrix(new_mat)
    return new_mat


def sub_bytes(matrix):
    sub_mat = []
    for row in matrix:
        sub_row = []
        for item in row:
            x = (item >> 4) & 0xF  # Grab top 4 bits.
            y = item & 0x0F        # Grab bottom 4 bits.
            sub_row.append(sbox[x][y])  # Use grabbed bits in table lookup
        sub_mat.append(sub_row)

    if(debug):
        print("AFTER SBOX")
        dump_matrix(sub_mat)
    return sub_mat


def shift_rows(matrix):
    shifted_mat = matrix  # Destructive function, so to preserve the matrix, we reassign the variable
    for x in range(len(shifted_mat)):
        shifted_row = shifted_mat[x]
        for itr in range(x):
            shifted_row.append(shifted_row.pop(0))

    if(debug):
        print("AFTER SHIFT")
        dump_matrix(shifted_mat)
    return shifted_mat


def mix_columns(matrix):
    result_array = []
    for i in range(len(matrix)):
        result_row = []
        for j in range(len(matrix)):
            res = 0
            for k in range(len(matrix)):
                if(mix_col_mat[i][k] & 0b10):  # Handles 2 and 3
                    res = matrix[k][j] << 1    # Shift left 1.
                if(mix_col_mat[i][k] & 0b1):   # Handles 1 and 3
                    res = matrix[k][j] ^ res   # Add original

                # Check high bit
                if(res & 0b100000000):
                    res ^= 0b100011011
            result_row.append(res)
        result_array.append(result_row)

    if(debug):
        print("AFTER MIX")
        dump_matrix(result_array)
    return result_array


def add_round_key(matrix, round_key):
    added_mat = []
    for row in range(len(matrix)):
        added_row = []
        for col in range(len(matrix)):
            added_row.append(matrix[row][col] ^ round_key[row][col])
        added_mat.append(added_row)

    return added_mat


def create_matrix(data, convert=False, text=False, key=False):
    mat = []
    i = 0
    while i < len(data):
        if(not text):
            try:
                mat[i % 4].append(data[i:i + 2])
                mat[(i + 1) % 4].append(data[i + 2:i + 4])
                mat[(i + 2) % 4].append(data[i + 4:i + 6])
                mat[(i + 3) % 4].append(data[i + 6:i + 8])
            except IndexError:  # Stupid workaround to get initial column.
                mat.append([data[i:i + 2]])
                mat.append([data[i + 2:i + 4]])
                mat.append([data[i + 4:i + 6]])
                mat.append([data[i + 6:i + 8]])
            i += 4
        else:
            try:
                mat[i % 4].append(data[i])
                mat[(i + 1) % 4].append(data[i + 1])
                mat[(i + 2) % 4].append(data[i + 2])
                mat[(i + 3) % 4].append(data[i + 3])
            except IndexError:  # Stupid workaround to get initial column.
                mat.append([data[i]])
                mat.append([data[i + 1]])
                mat.append([data[i + 2]])
                mat.append([data[i + 3]])
        i += 4

    # Sometimes we'll need to convert a key from hex strings to integers, step into here.
    if(convert):
        for row in range(len(mat)):
            for elem in range(len(mat[row])):
                if(text):
                    mat[row][elem] = ord(mat[row][elem])
                else:
                    mat[row][elem] = int(mat[row][elem], 16)

    if(debug):
        print("NEW MATRIX")
        dump_matrix(mat)

    return mat


def dump_matrix(matrix):
    for row in matrix:
        for item in row:
            print('0x{0:2x} '.format(item), end='')  # Fuck you flake8 this is valid
            pass
        print('')
    print('')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description='''\
    Use AES to encrypt a string. Pass in a string as well as a key.
    ''')
    parser.add_argument('plaintext', help='Plaintext you want to encrypt.')
    parser.add_argument('key', help='128/192/256-bit key to use.')
    parser.add_argument('--debug', help='Set debug level.', action="store_true")
    parser.add_argument('--key_expansion', help='Set debug level.', action="store_true")
    args = parser.parse_args()
    if(args.debug):
        print("Debug mode ON")
        debug = 1
    if(args.key_expansion):
        print("Key expansion printing ON")
        key_expansion = 1
    if(not len(args.key) == 32):
        print("Key is improper length. Exiting...")
        if(debug):
            print("Key is", len(args.key), "chars long")

    # Create array of blocks of plaintext.
    blocks = []
    ciphertext = []
    i = 0
    iterations = 10
    key_matrix = create_matrix(args.key, convert=True, key=True)

    padded_text = args.plaintext.ljust(len(args.plaintext) + (16 - len(args.plaintext)) % 16, '\0')  # Pad with NUL so it can be properly divvied.
    while i < len(padded_text):
        blocks.append(padded_text[i:i + 16])  # Take 16 chars chars, this gives us the 128 bytes we need.
        i += 16

    for block in blocks:
        # Initial round
        block = create_matrix(block, convert=True, text=True)
        block = add_round_key(block, key_matrix)
        key_expanded = expand_key(key_matrix, 0)
        if(debug):
            print("Initial round complete. Beginning full process.")

        for round_count in range(1, iterations):
            sub_mat = sub_bytes(block)
            shift_mat = shift_rows(sub_mat)
            mix_mat = mix_columns(shift_mat)
            block = add_round_key(mix_mat, key_expanded)
            key_expanded = expand_key(key_expanded, round_count)

        # Final round
        sub_mat = sub_bytes(block)
        shift_mat = shift_rows(sub_mat)
        ciphertext.append(add_round_key(shift_mat, key_expanded))

    flattened_ciphertext = ""
    for block in ciphertext:
        for col in range(len(block)):
            for row in range(len(block)):
                flattened_ciphertext += chr(block[col][row])

    print("Ciphertext is", repr(flattened_ciphertext))
