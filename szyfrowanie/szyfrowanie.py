#!/usr/bin/env python3

import argparse


def get_from_hex(to_encode: str):
    try:
        val = int(to_encode, 16)
        return bin(val)
    except Exception:
        raise Exception("Nie można uzyskać liczby binarnej z formy heksadecymalnej! "
                        "Proszę się upewnić czy wpisana wartość jest cyfrą")


def get_from_bin(to_encode: str):
    try:
        val = int(to_encode, 2)
        return bin(val)
    except Exception:
        raise Exception("Nie można uzyskać liczby binarnej z formy binarnej! "
                        "Proszę się upewnić czy wpisana wartość jest cyfrą")


def get_from_dec(to_encode: str):
    try:
        val = int(to_encode)
        return bin(val)
    except Exception:
        raise Exception("Nie można uzyskać liczby binarnej z formy dziesiętnej! "
                        "Proszę się upewnić czy wpisana wartość jest cyfrą")


def get_decimal_presentation_format(bin_list: list):
    bin_list = list(map(lambda x: str(int(x)), bin_list))
    return int("".join(bin_list), 2)


def get_binary_presentation_format(bin_list: list):
    bin_list = list(map(lambda x: str(int(x)), bin_list))
    return bin(int("".join(bin_list), 2))


def get_binary_format(to_encode: str):
    first_char: str = to_encode[0]
    if first_char in ['b', 'h']:
        to_bin_func = get_from_bin if first_char == 'b' else get_from_hex
        bin_form = to_bin_func(to_encode[1:])
    else:
        bin_form = get_from_dec(to_encode)
    bin_form = list(bin_form[2:])
    return list(map(lambda x: int(x) == 1, bin_form))


def make_up_number(data, required_size=8):
    size_of_data = len(data)
    if size_of_data == required_size:
        return data
    missing = required_size - size_of_data
    missing = [False] * missing
    return missing + data


def encrypt_func_one(x1: bool, x2: bool, x3: bool, x4: bool, key: bool):
    return x1 ^ (x1 * x3) ^ (x2 * x4) ^ (x2 * x3 * x4) ^ (x1 * x2 * x3 * x4) ^ key


def encrypt_func_two(x1: bool, x2: bool, x3: bool, x4: bool, key: bool):
    return x2 ^ (x1 * x3) ^ (x1 * x2 * x4) ^ (x1 * x3 * x4) ^ (x1 * x2 * x3 * x4) ^ key


def encrypt_func_three(x1: bool, x2: bool, x3: bool, x4: bool, key: bool):
    return 1 ^ x3 ^ (x1 * x4) ^ (x1 * x2 * x4) ^ (x1 * x2 * x4) ^ (x1 * x2 * x3 * x4) ^ key


def encrypt_func_four(x1: bool, x2: bool, x3: bool, x4: bool, key: bool):
    return 1 ^ (x1 * x2) ^ (x3 * x4) ^ (x1 * x2 * x4) ^ (x1 * x3 * x4) ^ (x1 * x2 * x3 * x4) ^ key


def rotate_key(key: list):
    first_bit = key[0]
    key = key[1:]
    key.append(first_bit)
    return key


def get_rotated_key(key: list, rotated_keys: list, rounds=8):
    if rounds == 1:
        rotated_keys.append(rotate_key(key))
        return rotated_keys
    if rounds % 2 == 0:
        key_half_size = len(key) // 2
        rotated_key_1 = rotate_key(key[0:key_half_size])
        rotated_key_2 = rotate_key(key[key_half_size:])
        rotated_key = rotated_key_1 + rotated_key_2
    else:
        rotated_key = rotate_key(key)

    rotated_keys.append(rotated_key)
    return get_rotated_key(
        rotated_key,
        rotated_keys,
        rounds - 1,
    )


def get_key_for_current_rotation(key):
    return [key[1], key[3], key[5], key[7]]


def encrypt(data, key):
    x1, x2, x3, x4 = data[0:4]
    x5, x6, x7, x8 = data[4:]
    current_key = get_key_for_current_rotation(key)
    f1 = encrypt_func_one(x5, x6, x7, x8, current_key[0])
    f2 = encrypt_func_two(x5, x6, x7, x8, current_key[1])
    f3 = encrypt_func_three(x5, x6, x7, x8, current_key[2])
    f4 = encrypt_func_four(x5, x6, x7, x8, current_key[3])
    x1 = bool(f1) ^ x1
    x2 = bool(f2) ^ x2
    x3 = bool(f3) ^ x3
    x4 = bool(f4) ^ x4
    return data[4:] + [x1, x2, x3, x4]


def decrypt(data, key):
    x1, x2, x3, x4 = data[4:]
    x5, x6, x7, x8 = data[0:4]
    current_key = get_key_for_current_rotation(key)
    f1 = encrypt_func_one(x5, x6, x7, x8, current_key[0])
    f2 = encrypt_func_two(x5, x6, x7, x8, current_key[1])
    f3 = encrypt_func_three(x5, x6, x7, x8, current_key[2])
    f4 = encrypt_func_four(x5, x6, x7, x8, current_key[3])
    x1 = bool(f1) ^ x1
    x2 = bool(f2) ^ x2
    x3 = bool(f3) ^ x3
    x4 = bool(f4) ^ x4
    return [x1, x2, x3, x4] + data[0:4]


def encrypt_data(data, key, rounds=8):
    rotated_key = get_rotated_key(key, [], 8)
    while rounds > 0:
        data = encrypt(data, rotated_key[rounds-1])
        rounds -= 1
    return data


def decrypt_data(data, key, rounds=8):
    rotated_key = get_rotated_key(key, [], 8)
    rotated_key.reverse()
    while rounds > 0:
        data = decrypt(data, rotated_key[rounds-1])
        rounds -= 1
    return data


def mockup_data(n):
    return make_up_number(get_binary_format(f"{n}"))


def main(args: argparse.Namespace):
    data_to_encrypt, data_to_decrypt, key = [None] * 3

    try:
        key = get_binary_format(args.key) if args.key else [0]
        data_to_encrypt = get_binary_format(args.encrypt) if args.encrypt else None
        data_to_decrypt = get_binary_format(args.decrypt) if args.decrypt else None
    except Exception as e:
        print(f"Wystąpił problem: {e}")
        exit(2)

    key = make_up_number(key)

    if data_to_encrypt:
        data_to_encrypt = make_up_number(data_to_encrypt)
        encrypted = encrypt_data(data_to_encrypt, key)
        encrypted_decimal = get_decimal_presentation_format(encrypted)
        encrypted_binary = get_binary_presentation_format(encrypted)
        print(f"Zaszyfrowana wartość: {encrypted_decimal} - {encrypted_binary}")

    if data_to_decrypt:
        data_to_decrypt = make_up_number(data_to_decrypt)
        decrypted = decrypt_data(data_to_decrypt, key)
        decrypted_decimal = get_decimal_presentation_format(decrypted)
        decrypted_binary = get_binary_presentation_format(decrypted)
        print(f"Odszyfrowana wartość: {decrypted_decimal} - {decrypted_binary}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Program do zaszyfrowania wartości, dopuszczalne wartości dla klucza i elementu do zaszyfrowania\n" \
              "\t Binarna - przyklad b10\n" \
              "\t Decymalna - przyklad 10\n" \
              "\t Heksadecymalna - przyklad h10",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-e', '--encrypt', help="Wartość do zakodowania", action='store'
    )
    parser.add_argument(
        '-d', '--decrypt', help="Wartość do odkodowania", action='store'
    )
    parser.add_argument(
        '-k', '--key', help="Klucz", action='store'
    )
    args = parser.parse_args()
    main(args)
