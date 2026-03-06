#ifndef CRYPTOMANAGER_H
#define CRYPTOMANAGER_H

#include <QString>

/**
 * @class CryptoManager
 * @brief Синглтон для шифрования/дешифрования файлов с использованием AES-256-CBC
 *
 * Класс управляет криптографическими операциями, используя OpenSSL.
 * Ключ и вектор инициализации (IV) генерируются на основе пароля.
 */
class CryptoManager {
private:
    static CryptoManager* instance;     ///< Указатель на единственный экземпляр (синглтон)

    unsigned char key[32];              ///< Ключ AES-256 (32 байта)
    unsigned char iv[16];               ///< Вектор инициализации для CBC режима (16 байт)
    bool keyInitialized;                ///< Флаг готовности ключа к использованию

    /**
     * @brief Приватный конструктор (синглтон)
     */
    CryptoManager();

    /**
     * @brief Приватный деструктор
     */
    ~CryptoManager();

    /**
     * @brief Безопасное обнуление памяти (защита от оптимизации компилятора)
     * @param ptr Указатель на память
     * @param size Размер обнуляемой области
     */
    void secureZero(void* ptr, size_t size);

    /**
     * @brief Генерация ключа и IV из пароля
     * @param password Пароль пользователя
     * @return true при успешной генерации
     *
     * Использует SHA-256 для ключа и SHA-1 для IV.
     */
    bool deriveKeyFromPassword(const QString& password);

    /**
     * @brief Внутренняя проверка, зашифрован ли файл (по маркеру в начале)
     * @param filePath Путь к файлу
     * @return true если файл содержит маркер зашифрованного файла
     */
    bool isFileEncryptedInternal(const QString& filePath) const;

public:
    // Запрет копирования и присваивания
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    /**
     * @brief Получение экземпляра синглтона
     * @return Указатель на единственный экземпляр CryptoManager
     */
    static CryptoManager* getInstance();

    /**
     * @brief Уничтожение экземпляра синглтона
     */
    static void destroyInstance();

    /**
     * @brief Статическая проверка, зашифрован ли файл
     * @param filePath Путь к файлу
     * @return true если файл зашифрован
     */
    static bool isFileEncrypted(const QString& filePath);

    /**
     * @brief Инициализация крипто-менеджера паролем
     * @param password Пароль для генерации ключей
     * @return true при успешной инициализации
     */
    bool initialize(const QString& password);

    /**
     * @brief Шифрование файла
     * @param inputPath Путь к исходному файлу
     * @param outputPath Путь к зашифрованному файлу (возвращается)
     * @return true при успешном шифровании
     *
     * Добавляет маркер в начало файла и шифрует содержимое AES-256-CBC.
     * Исходный файл заменяется зашифрованным.
     */
    bool encryptFile(const QString& inputPath, QString& outputPath);

    /**
     * @brief Дешифрование файла
     * @param inputPath Путь к зашифрованному файлу
     * @param outputPath Путь к расшифрованному файлу (возвращается)
     * @return true при успешном дешифровании
     *
     * Проверяет маркер, удаляет его и дешифрует содержимое.
     * Зашифрованный файл заменяется расшифрованным.
     */
    bool decryptFile(const QString& inputPath, QString& outputPath);
};

#endif // CRYPTOMANAGER_H
