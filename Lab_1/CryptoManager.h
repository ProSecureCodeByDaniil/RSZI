#ifndef CRYPTOMANAGER_H
#define CRYPTOMANAGER_H

#include <QString>

class CryptoManager {
private:
    static CryptoManager* instance;

    unsigned char key[32];
    unsigned char iv[16];
    bool keyInitialized;

    CryptoManager();
    ~CryptoManager();

    void secureZero(void* ptr, size_t size);
    bool deriveKeyFromPassword(const QString& password);
    bool isFileEncryptedInternal(const QString& filePath) const;

public:
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    static CryptoManager* getInstance();
    static void destroyInstance();

    static bool isFileEncrypted(const QString& filePath);

    bool initialize(const QString& password);
    bool encryptFile(const QString& inputPath, QString& outputPath);
    bool decryptFile(const QString& inputPath, QString& outputPath);
};

#endif // CRYPTOMANAGER_H
