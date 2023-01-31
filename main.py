import logging

default_logger = logging.getLogger('Default vigenere cipher logger')
default_logger.setLevel(logging.INFO)


class VigenereCipher:
    """
    :param message - your message, in all cases, :param is_encrypted to False of True depend on your case
    :param cipher_key - key to encrypt/decrypt message
    :param logger - you can set up your own logger
    """
    def __init__(self, message: str, cipher_key: str, is_encrypted: bool, logger: logging.Logger = default_logger):
        if is_encrypted:
            self.__message = None
            self.__encrypted_message = message
        else:
            self.__message = message
            self.__encrypted_message = None
        self.__cipher_key = cipher_key.upper()
        self.logger = logger

    @property
    def message(self):
        return self.__message

    @property
    def cipher_key(self):
        return self.__cipher_key

    @property
    def encrypted_message(self):
        return self.__encrypted_message

    def __rounded_generator(self):
        current_index = 0
        while True:
            yield self.cipher_key[current_index]
            current_index += 1
            if current_index == len(self.cipher_key):
                current_index = 0

    @staticmethod
    def __encrypt_symbol(anchor_symbol: str, symbol: str):
        if not symbol.isalpha():
            return symbol
        anchor_symbol, symbol = anchor_symbol.upper(), symbol.upper()
        symbol_pos = ord(symbol) - 65
        sum_of_symbols = ord(anchor_symbol) + symbol_pos
        if sum_of_symbols > 90:
            res = chr(65 + (sum_of_symbols - 91))
            return res
        return chr(sum_of_symbols)

    @staticmethod
    def __decrypt_symbol(anchor_symbol: str, symbol: str):
        if not symbol.isalpha():
            return symbol
        shift = ord(anchor_symbol) - 65
        real_symbol = chr(ord(symbol) - shift)
        if ord(real_symbol) < 65:
            return chr(91 - (65 - ord(real_symbol)))
        return real_symbol

    def encrypt(self):
        if self.__message is None:
            self.logger.info('Cannot use encrypt method, message already encrypted!!')
            return None
        result = ""
        g_key = self.__rounded_generator()
        for char in self.__message:
            if char.isalpha():
                result += self.__encrypt_symbol(next(g_key), char)
            else:
                result += char
        self.__encrypted_message = result
        return result

    def decrypt(self):
        if self.__encrypted_message is None:
            self.logger.info('Cannot use decrypt method, message already decrypted!')
            return None
        result = ""
        g_key = self.__rounded_generator()
        for char in self.__encrypted_message:
            if char.isalpha():
                result += self.__decrypt_symbol(next(g_key), char)
            else:
                result += char
        self.__message = result
        return result


if __name__ == "__main__":
    action = input("Encrypt or Decrypt(E/D): ")
    if action.upper() == 'E':
        raw_message = input("Your message: ")
        encrypt_key = input("Your encrypt key(only alphabetic symbols): ")
        while not encrypt_key.isalpha():
            encrypt_key = input("Repeat.Your encrypt key(only alphabetic symbols and no spaces!): ")
        letter = VigenereCipher(raw_message, encrypt_key, False)
        letter.encrypt()
        print(f"Your encrypted message {letter.encrypted_message}")
    elif action.upper() == 'D':
        enc_message = input("Your encrypted message: ")
        decrypt_key = input("Your decrypt key(only alphabetic symbols): ")
        while not decrypt_key.isalpha():
            decrypt_key = input("Repeat.Your encrypt key(only alphabetic symbols and no spaces!): ")
        letter = VigenereCipher(enc_message, decrypt_key, True)
        letter.decrypt()
        print(f"Your decrypted message {letter.message}")
    else:
        print("Unknown action")
