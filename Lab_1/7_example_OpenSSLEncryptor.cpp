/*
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef _WIN32
#include <windows.h>
#endif

// Класс для шифрования/дешифрования строк с использованием AES-256-CBC
class OpenSSLEncryptor {
private:
    unsigned char key[32];  // AES-256 ключ (32 байта)
    unsigned char iv[16];   // Вектор инициализации (16 байт)
    bool keyInitialized;

    // Безопасное обнуление памяти
    void secureZero(void* ptr, size_t size) {
        if (ptr) {
            volatile unsigned char* vptr = static_cast<volatile unsigned char*>(ptr);
            while (size--) *vptr++ = 0;
        }
    }


    // Генерация ключа и IV из пароля
    bool deriveKeyFromPassword(const std::string& password) {
        if (password.empty()) return false;

        // SHA-256 для ключа (32 байта)
        SHA256(reinterpret_cast<const unsigned char*>(password.c_str()),
               password.size(), key);

        // SHA-1 для IV (берём первые 16 байт из 20)
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(password.c_str()),
             password.size(), hash);
        memcpy(iv, hash, 16);

        keyInitialized = true;
        return true;
    }

public:
    OpenSSLEncryptor() : keyInitialized(false) {
        secureZero(key, sizeof(key));
        secureZero(iv, sizeof(iv));
    }

    ~OpenSSLEncryptor() {
        secureZero(key, sizeof(key));
        secureZero(iv, sizeof(iv));
        keyInitialized = false;
    }

    // Инициализация паролем
    bool initialize(const std::string& password) {
        return deriveKeyFromPassword(password);
    }

    // Шифрование строки
    // Исходный текст
    // Зашифрованные данные (включая маркер в начале)
    std::vector<unsigned char> encrypt(const std::string& plaintext) {
        std::vector<unsigned char> result;

        if (!keyInitialized) {
            std::cout << "Ошибка: не инициализирован" << std::endl;
            return result;
        }

        // Маркер зашифрованного файла
        const unsigned char marker[] = {0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04};

        // Добавляем маркер в начало
        result.insert(result.end(), marker, marker + 8);

        // Создаём контекст шифрования
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return result;

        // Инициализация шифрования
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }

        // Буфер для зашифрованных данных
        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int outLen = 0;
        int totalLen = 0;

        // Шифруем данные
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen,
                              reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                              plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
        totalLen += outLen;

        // Финализируем шифрование
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + totalLen, &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }
        totalLen += outLen;

        // Добавляем зашифрованные данные в результат
        result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + totalLen);

        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    // Дешифрование строки
    // Зашифрованные данные (с маркером)
    // Расшифрованный текст
    std::string decrypt(const std::vector<unsigned char>& ciphertext) {
        if (!keyInitialized || ciphertext.size() < 8) {
            std::cout << "Ошибка: не инициализирован или данные повреждены" << std::endl;
            return "";
        }

        // Проверяем маркер
        const unsigned char expectedMarker[] = {0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04};
        if (memcmp(ciphertext.data(), expectedMarker, 8) != 0) {
            std::cout << "Ошибка: неверный маркер (файл не зашифрован)" << std::endl;
            return "";
        }

        // Создаём контекст дешифрования
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";

        // Инициализация дешифрования
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }

        // Пропускаем маркер (8 байт)
        std::vector<unsigned char> plaintext(ciphertext.size());
        int outLen = 0;
        int totalLen = 0;

        // Дешифруем данные
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen,
                              ciphertext.data() + 8, ciphertext.size() - 8) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        totalLen += outLen;

        // Финализируем дешифрование
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLen, &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        totalLen += outLen;

        EVP_CIPHER_CTX_free(ctx);

        return std::string(reinterpret_cast<char*>(plaintext.data()), totalLen);
    }
};

int main() {
    OpenSSLEncryptor crypto;

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Ввод пароля
    std::string password;
    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);

    if (!crypto.initialize(password)) {
        std::cout << "Ошибка инициализации!" << std::endl;
        return 1;
    }
    std::cout << "Крипто-менеджер инициализирован" << std::endl;

    // Ввод сообщения
    std::string message;
    std::cout << "\nВведите сообщение для шифрования: ";
    std::getline(std::cin, message);

    // Шифрование
    std::vector<unsigned char> encrypted = crypto.encrypt(message);
    std::cout << "\nЗашифрованное сообщение (" << encrypted.size() << " байт): ";
        for (size_t i = 0; i < std::min(encrypted.size(), size_t(50)); i++) {
        std::cout << std::hex << (int)encrypted[i] << " ";
    }
    if (encrypted.size() > 50) std::cout << "...";
    std::cout << std::dec << std::endl;

    // Дешифрование
    std::string decrypted = crypto.decrypt(encrypted);
    std::cout << "Расшифрованное сообщение: " << decrypted << std::endl;

        // Проверка
        if (message == decrypted) {
        std::cout << "\nУСПЕХ! Исходное и расшифрованное сообщения совпадают!" << std::endl;
    } else {
        std::cout << "\nОШИБКА! Сообщения не совпадают!" << std::endl;
    }

    return 0;
}
*/
