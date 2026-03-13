#include "CryptoManager.h"
#include "Logger.h"

#include <QFile>
#include <QFileInfo>
// #include <iostream> // Закомментировано: убираем лишний вывод
#include <vector>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/sha.h>

// Добавляем Windows заголовки для работы с атрибутами файлов
#ifdef Q_OS_WIN
#include <windows.h>
#endif

// Константа маркера зашифрованного файла (8 байт: 0xEF,0xBE,0xAD,0xDE,0x01,0x02,0x03,0x04)
const unsigned char ENCRYPTED_MARKER[] =
    {0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04};

const int MARKER_SIZE = 8;  ///< Размер маркера в байтах

// Инициализация статического члена
CryptoManager* CryptoManager::instance = nullptr;

/**
 * @brief Конструктор: обнуляет ключ и IV, сбрасывает флаг инициализации
 */
CryptoManager::CryptoManager() : keyInitialized(false)
{
    secureZero(key, sizeof(key));
    secureZero(iv, sizeof(iv));
}

/**
 * @brief Деструктор: безопасно затирает ключ и IV
 */
CryptoManager::~CryptoManager()
{
    secureZero(key, sizeof(key));
    secureZero(iv, sizeof(iv));
    keyInitialized = false;
}

/**
 * @brief Безопасное обнуление памяти с использованием volatile указателя
 *        для предотвращения оптимизации компилятором
 * @param ptr Указатель на память
 * @param size Количество байт для обнуления
 */
void CryptoManager::secureZero(void* ptr, size_t size)
{
    if (ptr)
    {
        volatile unsigned char* vptr =
            static_cast<volatile unsigned char*>(ptr);
        while (size--)
            *vptr++ = 0;
    }
}

/**
 * @brief Генерация ключа (32 байта) и IV (16 байт) из пароля
 * @param password Пароль пользователя
 * @return true при успешной генерации
 *
 * Ключ: SHA-256(пароль) → 32 байта
 * IV:   первые 16 байт SHA-1(пароль) → 16 байт
 */
bool CryptoManager::deriveKeyFromPassword(const QString& password)
{
    if (password.isEmpty())
    {
        // std::cout << "Ошибка: Пароль не может быть пустым" << std::endl; // Закомментировано: данный вывод больше не нужен
        return false;
    }

    QByteArray passwordBytes = password.toUtf8();

    // ===== Генерация ключа через SHA-256 =====
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    if (!mdctx)
        return false;

    const EVP_MD* md = EVP_sha256();

    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(mdctx,
                         passwordBytes.constData(),
                         passwordBytes.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, key, nullptr) != 1)
    {
        EVP_MD_CTX_destroy(mdctx);
        return false;
    }

    EVP_MD_CTX_destroy(mdctx);

    // ===== Генерация IV через SHA-1 =====
    mdctx = EVP_MD_CTX_create();
    if (!mdctx)
        return false;

    md = EVP_sha1();
    unsigned char hash[SHA_DIGEST_LENGTH];  // SHA-1 даёт 20 байт

    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(mdctx,
                         passwordBytes.constData(),
                         passwordBytes.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1)
    {
        EVP_MD_CTX_destroy(mdctx);
        return false;
    }

    EVP_MD_CTX_destroy(mdctx);

    memcpy(iv, hash, 16);  // Берём первые 16 байт SHA-1 для IV
    keyInitialized = true;

    passwordBytes.fill(0);  // Затираем пароль в памяти

    return true;
}

/**
 * @brief Получение экземпляра синглтона (создаёт при первом вызове)
 */
CryptoManager* CryptoManager::getInstance()
{
    if (!instance)
        instance = new CryptoManager();

    return instance;
}

/**
 * @brief Уничтожение экземпляра синглтона
 */
void CryptoManager::destroyInstance()
{
    delete instance;
    instance = nullptr;
}

/**
 * @brief Внутренний метод проверки, зашифрован ли файл
 * @param filePath Путь к файлу
 * @return true если первые MARKER_SIZE байт совпадают с ENCRYPTED_MARKER
 */
bool CryptoManager::isFileEncryptedInternal(const QString& filePath) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
        return false;

    unsigned char marker[MARKER_SIZE];
    qint64 bytesRead =
        file.read(reinterpret_cast<char*>(marker), MARKER_SIZE);

    file.close();

    if (bytesRead != MARKER_SIZE)
        return false;

    return memcmp(marker,
                  ENCRYPTED_MARKER,
                  MARKER_SIZE) == 0;
}

/**
 * @brief Статический метод для внешней проверки
 */
bool CryptoManager::isFileEncrypted(const QString& filePath)
{
    return getInstance()->isFileEncryptedInternal(filePath);
}

/**
 * @brief Проверка, можно ли изменять файл (не защищен ли он системой)
 * @param filePath Путь к файлу
 * @return true если файл можно изменять
 */
bool CryptoManager::isFileWritable(const QString& filePath)
{
    QFileInfo fileInfo(filePath);

    // Проверяем атрибуты файла
    if (fileInfo.isReadable() && fileInfo.isWritable()) {
        // Дополнительная проверка: пытаемся открыть для записи в режиме ReadWrite
        QFile file(filePath);
        if (file.open(QIODevice::ReadWrite)) {
            file.close();
            return true;
        }
    }

    return false;
}

/**
 * @brief Проверка, является ли файл системным или защищенным
 * @param filePath Путь к файлу
 * @return true если файл защищен и не должен обрабатываться
 */
bool CryptoManager::isProtectedSystemFile(const QString& filePath)
{
    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();

    // Список системных файлов, которые нельзя обрабатывать
    static const QStringList protectedFiles = {
        // "ProSecureCodeByDaniil.ini" // можно добавлять например отдельные файлы
        ".gitattributes",
        ".gitignore"
    };

    // Проверяем по имени
    for (const QString& protectedName : protectedFiles) {
        if (fileName.compare(protectedName, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }

    // Проверяем атрибуты Windows
    if (fileInfo.isHidden() || fileInfo.isSymLink() || fileInfo.isShortcut()) {
        // Для скрытых файлов проверяем дополнительно
        DWORD attributes = GetFileAttributesW(filePath.toStdWString().c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            if (attributes & FILE_ATTRIBUTE_SYSTEM ||
                attributes & FILE_ATTRIBUTE_DEVICE ||
                attributes & FILE_ATTRIBUTE_TEMPORARY) {
                return true;
            }
        }
    }

    // Проверяем права доступа
    if (!isFileWritable(filePath)) {
        // Если файл не доступен для записи, считаем его защищенным
        return true;
    }

    return false;
}

/**
 * @brief Инициализация паролем (публичный интерфейс для deriveKeyFromPassword)
 */
bool CryptoManager::initialize(const QString& password)
{
    return deriveKeyFromPassword(password);
}

/**
 * @brief Шифрование файла
 * @param inputPath Исходный файл
 * @param outputPath Возвращаемый путь (тот же inputPath при успехе)
 * @return true при успешном шифровании
 *
 * Алгоритм:
 * 1. Проверка инициализации
 * 2. Проверка, не защищен ли файл системой
 * 3. Проверка, не зашифрован ли уже файл
 * 4. Запись маркера в начало временного файла
 * 5. Шифрование данных AES-256-CBC
 * 6. Замена исходного файла временным
 */
bool CryptoManager::encryptFile(const QString& inputPath,
                                QString& outputPath)
{
    Logger* logger = Logger::getInstance();
    QString fileName = QFileInfo(inputPath).fileName();

    if (!keyInitialized)
    {
        // std::cout << "Ошибка: CryptoManager не инициализирован" // Закомментировано: данный вывод больше не нужен
        //           << std::endl;

        if (logger) {
            logger->logError("CryptoManager не инициализирован", fileName);
        }
        return false;
    }

    // ========== ПРОВЕРКА: Является ли файл системным/защищенным? ==========
    if (isProtectedSystemFile(inputPath))
    {
        // std::cout << "Файл защищен системой и не может быть изменен: " // Закомментировано
        //           << fileName.toStdString() << std::endl;

        // Записываем в соответствующий лог (encrypt лог) с указанием операции
        if (logger) {
            logger->logSkipped("Файл является системным или защищенным", fileName, LogOperation::Encrypt);
        }
        outputPath = inputPath;
        return true; // Возвращаем true, так как файл не должен обрабатываться
    }
    // ==========================================================================

    // Если файл уже зашифрован, ничего не делаем
    if (isFileEncryptedInternal(inputPath))
    {
        // std::cout << "Файл уже зашифрован: "                       // Закомментировано: данный вывод больше не нужен
        //           << QFileInfo(inputPath).fileName().toStdString()
        //           << std::endl;

        if (logger) {
            logger->logSkipped("Файл уже зашифрован", fileName, LogOperation::Encrypt);
        }
        outputPath = inputPath;
        return true; // Возвращаем true, так как файл уже в нужном состоянии
    }

    QFile inFile(inputPath);
    if (!inFile.open(QIODevice::ReadOnly))
    {
        if (logger) {
            logger->logError("Не удалось открыть файл для чтения", fileName);
        }
        return false;
    }

    QString tempPath = inputPath + ".tmp";  // Временный файл
    QFile outFile(tempPath);

    if (!outFile.open(QIODevice::WriteOnly))
    {
        if (logger) {
            logger->logError("Не удалось создать временный файл", fileName);
        }
        inFile.close();
        return false;
    }

    // Записываем маркер зашифрованного файла
    if (outFile.write(reinterpret_cast<const char*>(ENCRYPTED_MARKER),
                      MARKER_SIZE) != MARKER_SIZE)
    {
        if (logger) {
            logger->logError("Не удалось записать маркер шифрования", fileName);
        }
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    // Создаём контекст шифрования OpenSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        if (logger) {
            logger->logError("Не удалось создать контекст OpenSSL", fileName);
        }
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    // Инициализация шифрования AES-256-CBC
    if (EVP_EncryptInit_ex(ctx,
                           EVP_aes_256_cbc(),
                           nullptr,
                           key,
                           iv) != 1)
    {
        if (logger) {
            logger->logError("Ошибка инициализации шифрования", fileName);
        }
        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    const int BUFFER_SIZE = 4096;  // Размер буфера чтения
    std::vector<unsigned char> inBuffer(BUFFER_SIZE);
    std::vector<unsigned char> outBuffer(
        BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);  // Дополнительно для возможного дополнения

    int bytesRead, outLen;
    bool success = true;

    // Читаем исходный файл блоками и шифруем
    while ((bytesRead =
            inFile.read(reinterpret_cast<char*>(inBuffer.data()),
                        BUFFER_SIZE)) > 0)
    {
        if (EVP_EncryptUpdate(ctx,
                              outBuffer.data(),
                              &outLen,
                              inBuffer.data(),
                              bytesRead) != 1)
        {
            if (logger) {
                logger->logError("Ошибка при шифровании данных", fileName);
            }
            success = false;
            break;
        }

        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()),
                          outLen) != outLen)
        {
            if (logger) {
                logger->logError("Ошибка при записи зашифрованных данных", fileName);
            }
            success = false;
            break;
        }
    }

    // Финализация шифрования (обработка последнего блока с дополнением)
    if (success &&
        EVP_EncryptFinal_ex(ctx,
                            outBuffer.data(),
                            &outLen) == 1)
    {
        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()),
                          outLen) != outLen)
        {
            if (logger) {
                logger->logError("Ошибка при финализации шифрования", fileName);
            }
            success = false;
        }
    }
    else
    {
        if (success) {
            if (logger) {
                logger->logError("Ошибка при финализации шифрования (OpenSSL)", fileName);
            }
        }
        success = false;
    }

    EVP_CIPHER_CTX_free(ctx);  // Освобождаем контекст

    inFile.close();
    outFile.close();

    if (success)
    {
        QFile::remove(inputPath);          // Удаляем исходный файл
        QFile::rename(tempPath, inputPath); // Переименовываем временный
        outputPath = inputPath;
        // std::cout << "Файл успешно зашифрован" << std::endl; // Закомментировано: данный вывод больше не нужен

        // Логируем успешное шифрование файла
        if (logger) {
            logger->logEncrypt("Файл успешно зашифрован: " + fileName);
        }
    }
    else
    {
        QFile::remove(tempPath);  // Ошибка - удаляем временный файл
        // std::cout << "Ошибка при шифровании" << std::endl; // Закомментировано: данный вывод больше не нужен
        if (logger) {
            logger->logError("Ошибка при шифровании файла", fileName);
        }
    }

    return success;
}

/**
 * @brief Дешифрование файла
 * @param inputPath Зашифрованный файл
 * @param outputPath Возвращаемый путь (тот же inputPath при успехе)
 * @return true при успешном дешифровании
 *
 * Алгоритм:
 * 1. Проверка инициализации
 * 2. Проверка, не защищен ли файл системой
 * 3. Пропуск маркера (8 байт)
 * 4. Дешифрование данных AES-256-CBC
 * 5. Замена исходного файла временным
 */
bool CryptoManager::decryptFile(const QString& inputPath,
                                QString& outputPath)
{
    Logger* logger = Logger::getInstance();
    QString fileName = QFileInfo(inputPath).fileName();

    if (!keyInitialized)
    {
        if (logger) {
            logger->logError("CryptoManager не инициализирован", fileName);
        }
        return false;
    }

    // ========== ПРОВЕРКА: Является ли файл системным/защищенным? ==========
    if (isProtectedSystemFile(inputPath))
    {
        // std::cout << "Файл защищен системой и не может быть изменен: " // Закомментировано
        //           << fileName.toStdString() << std::endl;

        // Записываем в соответствующий лог (decrypt лог) с указанием операции
        if (logger) {
            logger->logSkipped("Файл является системным или защищенным", fileName, LogOperation::Decrypt);
        }
        outputPath = inputPath;
        return true; // Возвращаем true, так как файл не должен обрабатываться
    }
    // ==========================================================================

    // Если файл не зашифрован, ничего не делаем
    if (!isFileEncryptedInternal(inputPath))
    {
        if (logger) {
            logger->logSkipped("Файл не зашифрован", fileName, LogOperation::Decrypt);
        }
        outputPath = inputPath;
        return true; // Возвращаем true, так как файл уже в нужном состоянии
    }

    QFile inFile(inputPath);
    if (!inFile.open(QIODevice::ReadOnly))
    {
        if (logger) {
            logger->logError("Не удалось открыть файл для чтения", fileName);
        }
        return false;
    }

    // Пропускаем маркер (он нам больше не нужен)
    if (!inFile.seek(MARKER_SIZE))
    {
        if (logger) {
            logger->logError("Не удалось пропустить маркер в файле", fileName);
        }
        inFile.close();
        return false;
    }

    QString tempPath = inputPath + ".tmp";  // Временный файл
    QFile outFile(tempPath);

    if (!outFile.open(QIODevice::WriteOnly))
    {
        if (logger) {
            logger->logError("Не удалось создать временный файл", fileName);
        }
        inFile.close();
        return false;
    }

    // Создаём контекст дешифрования OpenSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        if (logger) {
            logger->logError("Не удалось создать контекст OpenSSL", fileName);
        }
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    // Инициализация дешифрования AES-256-CBC
    if (EVP_DecryptInit_ex(ctx,
                           EVP_aes_256_cbc(),
                           nullptr,
                           key,
                           iv) != 1)
    {
        if (logger) {
            logger->logError("Ошибка инициализации дешифрования", fileName);
        }
        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    const int BUFFER_SIZE = 4096;
    std::vector<unsigned char> inBuffer(BUFFER_SIZE);
    std::vector<unsigned char> outBuffer(
        BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

    int bytesRead, outLen;
    bool success = true;

    // Читаем зашифрованный файл блоками и дешифруем
    while ((bytesRead =
            inFile.read(reinterpret_cast<char*>(inBuffer.data()),
                        BUFFER_SIZE)) > 0)
    {
        if (EVP_DecryptUpdate(ctx,
                              outBuffer.data(),
                              &outLen,
                              inBuffer.data(),
                              bytesRead) != 1)
        {
            if (logger) {
                logger->logError("Ошибка при дешифровании данных", fileName);
            }
            success = false;
            break;
        }

        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()),
                          outLen) != outLen)
        {
            if (logger) {
                logger->logError("Ошибка при записи расшифрованных данных", fileName);
            }
            success = false;
            break;
        }
    }

    // Финализация дешифрования (проверка дополнения)
    if (success &&
        EVP_DecryptFinal_ex(ctx,
                            outBuffer.data(),
                            &outLen) == 1)
    {
        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()),
                          outLen) != outLen)
        {
            if (logger) {
                logger->logError("Ошибка при финализации дешифрования", fileName);
            }
            success = false;
        }
    }
    else
    {
        if (success) {
            if (logger) {
                logger->logError("Ошибка при финализации дешифрования (OpenSSL)", fileName);
            }
        }
        success = false;
    }

    EVP_CIPHER_CTX_free(ctx);

    inFile.close();
    outFile.close();

    if (success)
    {
        QFile::remove(inputPath);           // Удаляем зашифрованный файл
        QFile::rename(tempPath, inputPath);  // Переименовываем временный
        outputPath = inputPath;
        // std::cout << "Файл успешно расшифрован" << std::endl; // Закомментировано: данный вывод больше не нужен

        // Логируем успешное дешифрование файла
        if (logger) {
            logger->logDecrypt("Файл успешно расшифрован: " + fileName);
        }
    }
    else
    {
        QFile::remove(tempPath);  // Ошибка - удаляем временный файл
        // std::cout << "Ошибка при дешифровании" << std::endl; // Закомментировано: данный вывод больше не нужен

        if (logger) {
            logger->logError("Ошибка при дешифровании файла", fileName);
        }
    }

    return success;
}
