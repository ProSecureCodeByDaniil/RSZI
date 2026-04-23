/**
 * @file CryptoManager.h
 * @brief Главный модуль криптографических операций (синглтон)
 *
 * Отвечает за шифрование и дешифрование файлов с использованием AES-256-CBC.
 * Работает с паролем, генерируя ключ и вектор инициализации (IV).
 * Поддерживает рекурсивную обработку папок, проверку защищённых файлов,
 * ведение статистики и интеграцию с логгером.
 */

#ifndef CRYPTOMANAGER_H
#define CRYPTOMANAGER_H

#include <QString>
#include <QList>
#include <memory>
#include <cstddef>

struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

/**
 * @struct FileInfo
 * @brief Информация о файле при обходе директории
 */
struct FileInfo {
    QString path;            ///< Полный путь к файлу
    QString relativePath;    ///< Путь относительно корня обработки
    qint64 size;             ///< Размер в байтах
    bool isEncrypted;        ///< Зашифрован ли (проверка по маркеру)
};

/**
 * @enum OperationMode
 * @brief Режим работы программы
 */
enum class OperationMode {
    Encrypt,    ///< Шифрование (добавляет маркер)
    Decrypt,    ///< Дешифрование (удаляет маркер)
    None        ///< Режим не задан
};

/**
 * @struct ProcessingResult
 * @brief Результат массовой обработки файлов
 */
struct ProcessingResult {
    int totalFiles;         ///< Всего найдено файлов
    int successCount;       ///< Успешно обработано
    int skippedCount;       ///< Пропущено (уже в нужном состоянии)
    int protectedCount;     ///< Системных/защищённых файлов
    int errorCount;         ///< Фатальных ошибок

    ProcessingResult() : totalFiles(0), successCount(0), skippedCount(0), protectedCount(0), errorCount(0) {}
};

/**
 * @class CryptoManager
 * @brief Синглтон для управления шифрованием/дешифрованием
 *
 * Использует OpenSSL (EVP_aes_256_cbc).
 * Ключ и IV вычисляются из пароля через SHA-256 и SHA-1.
 * Маркер зашифрованного файла — 8 байт (0xEF,0xBE,0xAD,0xDE,0x01,0x02,0x03,0x04).
 */
class CryptoManager {
private:
    static CryptoManager* instance;

    unsigned char key[32];      ///< Ключ AES-256
    unsigned char iv[16];       ///< Вектор инициализации (CBC)
    bool keyInitialized;

    OperationMode currentMode;
    ProcessingResult result;
    QString folderPath;

    CryptoManager();
    ~CryptoManager();

    void secureZero(void* ptr, size_t size);
    bool deriveKeyFromPassword(const QString& password);
    bool isFileWritable(const QString& filePath);
    bool isProtectedSystemFile(const QString& filePath);
    void collectFilesInfo(const QString& path, const QString& basePath, QList<FileInfo>& files);
    bool processSingleFile(const QString& filePath, bool isEncrypt);

    bool encryptSingleFile(const QString& filePath) { return processSingleFile(filePath, true); }
    bool decryptSingleFile(const QString& filePath) { return processSingleFile(filePath, false); }

    std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> createCipherContext(bool isEncrypt);

public:
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    /**
     * @brief Получить единственный экземпляр (синглтон)
     * @return указатель на CryptoManager
     */
    static CryptoManager* getInstance();

    /**
     * @brief Уничтожить экземпляр (вызывать при завершении)
     */
    static void destroyInstance();

    /**
     * @brief Инициализация паролем (генерирует key и iv)
     * @param password Пароль пользователя (не сохраняется)
     * @return true если ключ успешно сгенерирован
     */
    bool initialize(const QString& password);

    /**
     * @brief Основной метод обработки папки (рекурсивно)
     * @param path Путь к папке
     * @param mode Encrypt или Decrypt
     * @return true если нет критических ошибок
     */
    bool processFolder(const QString& path, OperationMode mode);

    /**
     * @brief Проверить, зашифрован ли файл (по маркеру)
     * @param filePath Путь к файлу
     * @return true если маркер найден
     */
    bool isFileEncrypted(const QString& filePath) const;

    /**
     * @brief Получить статистику последней операции
     * @return структура ProcessingResult
     */
    const ProcessingResult& getResult() const { return result; }
};

#endif // CRYPTOMANAGER_H
