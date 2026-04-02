/*
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

// Простая XOR-шифровка
class SimpleEncryptor {
private:
    std::string key;

public:
    void setKey(const std::string& k) {
        key = k;
        std::cout << "Ключ установлен: " << key << std::endl;
    }

    // Шифрование: XOR с ключом
    std::string encrypt(const std::string& text) {
        std::string result = text;
        for (size_t i = 0; i < text.length(); i++) {
            result[i] = text[i] ^ key[i % key.length()];
        }
        return result;
    }

    // Дешифрование: повторный XOR (свойство XOR)
    std::string decrypt(const std::string& cipher) {
        return encrypt(cipher);  // XOR дважды даёт исходный текст
    }
};

int main() {
    SimpleEncryptor crypto;

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::string password;
    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);
    crypto.setKey(password);

    std::string message;
    std::cout << "Введите сообщение: ";
    std::getline(std::cin, message);

    // Шифрование
    std::string encrypted = crypto.encrypt(message);
    std::cout << "Зашифрованное сообщение: ";
    for (unsigned char c : encrypted) {
        std::cout << std::hex << (int)c << " ";
    }
    std::cout << std::endl;

    // Дешифрование
    std::string decrypted = crypto.decrypt(encrypted);
    std::cout << "Расшифрованное сообщение: " << decrypted << std::endl;

        return 0;
}
*/
