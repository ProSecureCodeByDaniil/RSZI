#include "CryptoManager.h"

#include <QFile>
#include <QFileInfo>
#include <iostream>
#include <vector>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/sha.h>

// Константа маркера зашифрованного файла
const unsigned char ENCRYPTED_MARKER[] =
    {0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04};

const int MARKER_SIZE = 8;

// Инициализация статического члена
CryptoManager* CryptoManager::instance = nullptr;

CryptoManager::CryptoManager() : keyInitialized(false)
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

bool CryptoManager::deriveKeyFromPassword(const QString& password)
{
    if (password.isEmpty())
    {
        std::cout << "Ошибка: Пароль не может быть пустым" << std::endl;
        return false;
    }

    QByteArray passwordBytes = password.toUtf8();

    // ===== SHA-256 -> KEY =====
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;

    const EVP_MD* md = EVP_sha256();

    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(mdctx,
                         passwordBytes.constData(),
                         passwordBytes.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, key, nullptr) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);

    // ===== SHA-1 -> IV =====
    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;

    md = EVP_sha1();
    unsigned char hash[SHA_DIGEST_LENGTH];

    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(mdctx,
                         passwordBytes.constData(),
                         passwordBytes.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);

    memcpy(iv, hash, 16);
    keyInitialized = true;

    passwordBytes.fill(0);

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

bool CryptoManager::isFileEncrypted(const QString& filePath)
{
    return getInstance()->isFileEncryptedInternal(filePath);
}

bool CryptoManager::initialize(const QString& password)
{
    return deriveKeyFromPassword(password);
}

bool CryptoManager::encryptFile(const QString& inputPath,
                                QString& outputPath)
{
    if (!keyInitialized)
    {
        std::cout << "Ошибка: CryptoManager не инициализирован"
                  << std::endl;
        return false;
    }

    if (isFileEncryptedInternal(inputPath))
    {
        std::cout << "Файл уже зашифрован: "
                  << QFileInfo(inputPath).fileName().toStdString()
                  << std::endl;
        outputPath = inputPath;
        return true;
    }

    QFile inFile(inputPath);
    if (!inFile.open(QIODevice::ReadOnly))
        return false;

    QString tempPath = inputPath + ".tmp";
    QFile outFile(tempPath);

    if (!outFile.open(QIODevice::WriteOnly))
    {
        inFile.close();
        return false;
    }

    if (outFile.write(reinterpret_cast<const char*>(ENCRYPTED_MARKER),
                      MARKER_SIZE) != MARKER_SIZE)
    {
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx,
                           EVP_aes_256_cbc(),
                           nullptr,
                           key,
                           iv) != 1)
    {
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
            success = false;
            break;
        }

        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()),
                          outLen) != outLen)
        {
            success = false;
            break;
        }
    }

    if (success &&
        EVP_EncryptFinal_ex(ctx,
                            outBuffer.data(),
                            &outLen) == 1)
    {
        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()),
                          outLen) != outLen)
            success = false;
    }
    else
        success = false;

    EVP_CIPHER_CTX_free(ctx);

    inFile.close();
    outFile.close();

    if (success)
    {
        QFile::remove(inputPath);
        QFile::rename(tempPath, inputPath);
        outputPath = inputPath;
        std::cout << "Файл успешно зашифрован" << std::endl;
    }
    else
    {
        QFile::remove(tempPath);
        std::cout << "Ошибка при шифровании" << std::endl;
    }

    return success;
}

bool CryptoManager::decryptFile(const QString& inputPath,
                                QString& outputPath)
{
    if (!keyInitialized)
        return false;

    if (!isFileEncryptedInternal(inputPath))
    {
        outputPath = inputPath;
        return true;
    }

    QFile inFile(inputPath);
    if (!inFile.open(QIODevice::ReadOnly))
        return false;

    if (!inFile.seek(MARKER_SIZE))
    {
        inFile.close();
        return false;
    }

    QString tempPath = inputPath + ".tmp";
    QFile outFile(tempPath);

    if (!outFile.open(QIODevice::WriteOnly))
    {
        inFile.close();
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        inFile.close();
        outFile.close();
        QFile::remove(tempPath);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx,
                           EVP_aes_256_cbc(),
                           nullptr,
                           key,
                           iv) != 1)
    {
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
            success = false;
            break;
        }

        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()),
                          outLen) != outLen)
        {
            success = false;
            break;
        }
    }

    if (success &&
        EVP_DecryptFinal_ex(ctx,
                            outBuffer.data(),
                            &outLen) == 1)
    {
        if (outFile.write(reinterpret_cast<char*>(outBuffer.data()),
                          outLen) != outLen)
            success = false;
    }
    else
        success = false;

    EVP_CIPHER_CTX_free(ctx);

    inFile.close();
    outFile.close();

    if (success)
    {
        QFile::remove(inputPath);
        QFile::rename(tempPath, inputPath);
        outputPath = inputPath;
        std::cout << "Файл успешно расшифрован" << std::endl;
    }
    else
    {
        QFile::remove(tempPath);
        std::cout << "Ошибка при дешифровании" << std::endl;
    }

    return success;
}
