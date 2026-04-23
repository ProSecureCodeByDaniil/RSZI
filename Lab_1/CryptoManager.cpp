/**
 * @file CryptoManager.cpp
 * Реализация всех криптографических операций.
 *
 * Основные блоки:
 * - deriveKeyFromPassword – генерация ключа и IV из пароля
 * - processSingleFile   – шифрование/дешифрование одного файла с временным файлом
 * - processFolder       – рекурсивный обход папки с учётом защищённых файлов
 * - isProtectedSystemFile – проверка скрытых/системных файлов (Windows)
 */

#include "CryptoManager.h"
#include "Logger.h"

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <vector>
#include <cstring>
#include <memory>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

// Совместимость со старыми версиями OpenSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

// Маркер зашифрованного файла (первые 8 байт)
const unsigned char ENCRYPTED_MARKER[] = {0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04};
const int MARKER_SIZE = 8;
const int BUFFER_SIZE = 4096;

// Синглтон
CryptoManager* CryptoManager::instance = nullptr;

CryptoManager::CryptoManager() : keyInitialized(false), currentMode(OperationMode::None)
{
    secureZero(key, sizeof(key));
    secureZero(iv, sizeof(iv));
}

CryptoManager::~CryptoManager()
{
    secureZero(key, sizeof(key));
    secureZero(iv, sizeof(iv));
    keyInitialized = false;
}

// Безопасное обнуление через volatile (не вырежется оптимизатором)
void CryptoManager::secureZero(void* ptr, size_t size)
{
    if (ptr)
    {
        volatile unsigned char* vptr = static_cast<volatile unsigned char*>(ptr);
        while (size--)
            *vptr++ = 0;
    }
}

// Генерация ключа (SHA-256) и IV (первые 16 байт SHA-1 от пароля)
bool CryptoManager::deriveKeyFromPassword(const QString& password)
{
    if (password.isEmpty())
        return false;

    QByteArray passwordBytes = password.toUtf8();

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;

    const EVP_MD* md = EVP_sha256();
    bool success = true;

    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, passwordBytes.constData(), passwordBytes.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, key, nullptr) != 1)
    {
        success = false;
    }

    EVP_MD_CTX_free(mdctx);
    if (!success)
        return false;

    // IV через SHA-1 (первые 16 байт)
    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;

    md = EVP_sha1();
    unsigned char hash[SHA_DIGEST_LENGTH];

    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, passwordBytes.constData(), passwordBytes.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);
    memcpy(iv, hash, 16);
    keyInitialized = true;

    passwordBytes.fill(0); // затираем копию пароля в памяти
    return true;
}

CryptoManager* CryptoManager::getInstance()
{
    if (!instance)
        instance = new CryptoManager();
    return instance;
}

void CryptoManager::destroyInstance()
{
    delete instance;
    instance = nullptr;
}

// Проверка маркера в начале файла
bool CryptoManager::isFileEncrypted(const QString& filePath) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
        return false;

    unsigned char marker[MARKER_SIZE];
    qint64 bytesRead = file.read(reinterpret_cast<char*>(marker), MARKER_SIZE);
    file.close();

    return (bytesRead == MARKER_SIZE) &&
           (memcmp(marker, ENCRYPTED_MARKER, MARKER_SIZE) == 0);
}

// Проверка, можно ли писать в файл (попыткой открыть на запись)
bool CryptoManager::isFileWritable(const QString& filePath)
{
    QFileInfo fileInfo(filePath);
    if (fileInfo.isReadable() && fileInfo.isWritable()) {
        QFile file(filePath);
        if (file.open(QIODevice::ReadWrite)) {
            file.close();
            return true;
        }
    }
    return false;
}

// Защищённые системные файлы (скрытые, .git*, системные атрибуты Windows)
bool CryptoManager::isProtectedSystemFile(const QString& filePath)
{
    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();

    static const QStringList protectedFiles = {".gitattributes", ".gitignore"};

    for (const QString& protectedName : protectedFiles) {
        if (fileName.compare(protectedName, Qt::CaseInsensitive) == 0)
            return true;
    }

    if (fileInfo.isHidden())
        return true;

#ifdef Q_OS_WIN
    DWORD attributes = GetFileAttributesW(filePath.toStdWString().c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        if (attributes & FILE_ATTRIBUTE_SYSTEM || attributes & FILE_ATTRIBUTE_DEVICE)
            return true;
    }
#endif

    return !isFileWritable(filePath);
}

bool CryptoManager::initialize(const QString& password)
{
    return deriveKeyFromPassword(password);
}

// Создание контекста OpenSSL (шифрование или дешифрование)
std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)>
CryptoManager::createCipherContext(bool isEncrypt)
{
    std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> ctx(
        EVP_CIPHER_CTX_new(),
        [](EVP_CIPHER_CTX* c) { if (c) EVP_CIPHER_CTX_free(c); }
        );

    if (!ctx)
        return {nullptr, nullptr};

    int initResult;
    if (isEncrypt)
        initResult = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv);
    else
        initResult = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key, iv);

    if (initResult != 1)
        return {nullptr, nullptr};

    return ctx;
}

// Ядро: шифрование или дешифрование одного файла с временным файлом
bool CryptoManager::processSingleFile(const QString& filePath, bool isEncrypt)
{
    Logger* logger = Logger::getInstance();
    QString fileName = QFileInfo(filePath).fileName();
    QString operationName = isEncrypt ? "шифрования" : "дешифрования";

    if (!keyInitialized)
    {
        if (logger) logger->logError("CryptoManager не инициализирован", fileName);
        return false;
    }

    QFile inFile(filePath);
    if (!inFile.open(QIODevice::ReadOnly))
    {
        if (logger) logger->logError("Не удалось открыть файл для чтения", fileName);
        return false;
    }

    // Для дешифрования пропускаем маркер (8 байт)
    if (!isEncrypt && !inFile.seek(MARKER_SIZE))
    {
        if (logger) logger->logError("Не удалось пропустить маркер в файле", fileName);
        inFile.close();
        return false;
    }

    QString tempPath = filePath + ".tmp";
    QFile outFile(tempPath);

    if (!outFile.open(QIODevice::WriteOnly))
    {
        if (logger) logger->logError("Не удалось создать временный файл", fileName);
        inFile.close();
        return false;
    }

    // При шифровании пишем маркер в начало
    if (isEncrypt)
    {
        if (outFile.write(reinterpret_cast<const char*>(ENCRYPTED_MARKER), MARKER_SIZE) != MARKER_SIZE)
        {
            if (logger) logger->logError("Не удалось записать маркер шифрования", fileName);
            inFile.close();
            outFile.close();
            QFile::remove(tempPath);
            return false;
        }
    }

    auto ctx = createCipherContext(isEncrypt);
    if (!ctx)
    {
        if (logger) logger->logError(QString("Не удалось создать контекст OpenSSL для %1").arg(operationName), fileName);
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    std::vector<unsigned char> inBuffer(BUFFER_SIZE);
    std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

    int bytesRead, outLen;
    bool success = true;

    // Основной цикл: читаем, шифруем/дешифруем, пишем
    while ((bytesRead = inFile.read(reinterpret_cast<char*>(inBuffer.data()), BUFFER_SIZE)) > 0)
    {
        int updateResult;
        if (isEncrypt)
            updateResult = EVP_EncryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), bytesRead);
        else
            updateResult = EVP_DecryptUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), bytesRead);

        if (updateResult != 1)
        {
            if (logger) logger->logError(QString("Ошибка при %1 данных").arg(operationName), fileName);
            success = false;
            break;
        }

        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen) != outLen)
        {
            if (logger) logger->logError(QString("Ошибка при записи %1 данных").arg(operationName), fileName);
            success = false;
            break;
        }
    }

    // Финализация (добивка блока)
    if (success)
    {
        int finalResult;
        if (isEncrypt)
            finalResult = EVP_EncryptFinal_ex(ctx.get(), outBuffer.data(), &outLen);
        else
            finalResult = EVP_DecryptFinal_ex(ctx.get(), outBuffer.data(), &outLen);

        if (finalResult == 1)
        {
            if (outLen > 0 && outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen) != outLen)
            {
                if (logger) logger->logError(QString("Ошибка при финализации %1").arg(operationName), fileName);
                success = false;
            }
        }
        else
        {
            if (logger) logger->logError(QString("Ошибка при финализации %1 (OpenSSL)").arg(operationName), fileName);
            success = false;
        }
    }

    inFile.close();
    outFile.close();

    // Если всё успешно — заменяем исходный файл временным
    if (success)
    {
        if (!QFile::remove(filePath))
        {
            if (logger) logger->logError("Не удалось удалить исходный файл", fileName);
            QFile::remove(tempPath);
            return false;
        }

        if (!QFile::rename(tempPath, filePath))
        {
            if (logger) logger->logError("Не удалось переименовать временный файл", fileName);
            QFile::remove(tempPath);
            return false;
        }

        if (logger)
        {
            if (isEncrypt)
                logger->logEncrypt("Файл успешно зашифрован: " + fileName);
            else
                logger->logDecrypt("Файл успешно расшифрован: " + fileName);
        }
    }
    else
    {
        QFile::remove(tempPath);
        if (logger) logger->logError(QString("Ошибка при %1 файла").arg(operationName), fileName);
    }

    return success;
}

// Рекурсивный сбор файлов
void CryptoManager::collectFilesInfo(const QString& path, const QString& basePath, QList<FileInfo>& files)
{
    QDir dir(path);
    if (!dir.exists())
        return;

    QFileInfoList entries = dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);

    for (const QFileInfo& entry : entries)
    {
        if (entry.isDir())
        {
            collectFilesInfo(entry.absoluteFilePath(), basePath, files);
        }
        else if (entry.isFile())
        {
            FileInfo fileInfo;
            fileInfo.path = entry.absoluteFilePath();
            fileInfo.relativePath = QDir(basePath).relativeFilePath(entry.absoluteFilePath());
            fileInfo.size = entry.size();
            fileInfo.isEncrypted = isFileEncrypted(entry.absoluteFilePath());
            files.append(fileInfo);
        }
    }
}

// Основной метод обработки папки (с учётом защищённых файлов и уже обработанных)
bool CryptoManager::processFolder(const QString& path, OperationMode mode)
{
    Logger* logger = Logger::getInstance();

    currentMode = mode;
    folderPath = path;
    result = ProcessingResult();

    if (!keyInitialized)
    {
        if (logger) logger->logError("CryptoManager не инициализирован. Вызовите initialize() перед processFolder()");
        std::cout << "[ОШИБКА] CryptoManager не инициализирован" << std::endl;
        return false;
    }

    QFileInfo folderInfo(folderPath);
    if (!folderInfo.exists() || !folderInfo.isDir())
    {
        if (logger) logger->logError("Указанная папка не существует или не является директорией: " + folderPath);
        std::cout << "[ОШИБКА] Указанная папка не существует или не является директорией" << std::endl;
        return false;
    }

    QList<FileInfo> files;
    collectFilesInfo(folderPath, folderPath, files);
    result.totalFiles = files.size();

    if (files.isEmpty())
    {
        std::cout << "В указанной папке нет файлов для обработки" << std::endl;
        if (logger) logger->logInfo("В указанной папке нет файлов для обработки: " + folderPath);
        return true;
    }

    std::cout << "Найдено файлов для обработки: " << files.size() << std::endl;

    QString operationName = (mode == OperationMode::Encrypt) ? "шифрования" : "дешифрования";
    std::cout << "Начинаю " << operationName.toStdString() << " файлов..." << std::endl;

    for (auto& file : files)
    {
        // Пропускаем защищённые системные файлы
        if (isProtectedSystemFile(file.path))
        {
            result.protectedCount++;
            result.skippedCount++;

            if (logger)
            {
                LogOperation logOp = (mode == OperationMode::Encrypt) ? LogOperation::Encrypt : LogOperation::Decrypt;
                logger->logSkipped("Файл является системным или защищенным", QFileInfo(file.path).fileName(), logOp);
            }
            continue;
        }

        bool needProcess = false;

        if (mode == OperationMode::Encrypt)
        {
            if (!file.isEncrypted)
                needProcess = true;
            else
            {
                result.skippedCount++;
                if (logger) logger->logSkipped("Файл уже зашифрован", QFileInfo(file.path).fileName(), LogOperation::Encrypt);
            }
        }
        else // Decrypt
        {
            if (file.isEncrypted)
                needProcess = true;
            else
            {
                result.skippedCount++;
                if (logger) logger->logSkipped("Файл не зашифрован", QFileInfo(file.path).fileName(), LogOperation::Decrypt);
            }
        }

        if (needProcess)
        {
            bool success = (mode == OperationMode::Encrypt) ? encryptSingleFile(file.path) : decryptSingleFile(file.path);
            if (success)
                result.successCount++;
            else
                result.errorCount++;
        }
    }

    std::cout << "Статистика: обработано " << result.totalFiles
              << " файлов (успешно: " << result.successCount
              << ", пропущено: " << result.skippedCount
              << " [из них системных/защищенных: " << result.protectedCount << "]"
              << ", ошибок: " << result.errorCount << ")" << std::endl;

    if (logger)
    {
        QString summary = (result.protectedCount > 0) ?
                              QString("Итого по операции %1: Успешно: %2, Пропущено: %3 (системных/защищенных: %4), Ошибок: %5")
                                  .arg(operationName).arg(result.successCount).arg(result.skippedCount)
                                  .arg(result.protectedCount).arg(result.errorCount) :
                              QString("Итого по операции %1: Успешно: %2, Пропущено: %3, Ошибок: %4")
                                  .arg(operationName).arg(result.successCount).arg(result.skippedCount).arg(result.errorCount);
        logger->logInfo(summary);
    }

    return (result.errorCount == 0);
}
