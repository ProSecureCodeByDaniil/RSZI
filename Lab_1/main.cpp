#include <QCoreApplication>
#include <QFileInfo>
#include <QDir>
#include <QFile>
#include <QCryptographicHash>
#include <QTextStream>
#include <QDateTime>
#include <QList>
#include <iostream>
#include <windows.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <vector>

// Константа для метки зашифрованного файла (внедряется в начало файла)
const unsigned char ENCRYPTED_MARKER[] = {0xEF, 0xBE, 0xAD, 0xDE, 0x01, 0x02, 0x03, 0x04};
const int MARKER_SIZE = 8;

// Структура для хранения информации о файле
struct FileInfo {
    QString path;
    QString relativePath;
    QString hash;
    qint64 size;
    bool isEncrypted; // Флаг, указывающий, зашифрован ли файл
};

// Класс-синглтон для шифрования/дешифрования AES-256
class CryptoManager {
private:
    static CryptoManager* instance;
    unsigned char key[32]; // 256 бит = 32 байта
    unsigned char iv[16];  // 128 бит = 16 байт
    bool keyInitialized;

    // Приватный конструктор
    CryptoManager() : keyInitialized(false) {
        secureZero(key, sizeof(key));
        secureZero(iv, sizeof(iv));
    }

    // Безопасная очистка памяти
    void secureZero(void* ptr, size_t size) {
        if (ptr) {
            volatile unsigned char* vptr = static_cast<volatile unsigned char*>(ptr);
            while (size--) {
                *vptr++ = 0;
            }
        }
    }

    // Генерация ключа и IV из пароля с использованием нового EVP API
    bool deriveKeyFromPassword(const QString& password) {
        if (password.isEmpty()) {
            std::cout << "Ошибка: Пароль не может быть пустым" << std::endl;
            return false;
        }

        QByteArray passwordBytes = password.toUtf8();

        // Используем EVP API для SHA256
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            std::cout << "Ошибка: Не удалось создать контекст EVP_MD" << std::endl;
            return false;
        }

        const EVP_MD* md = EVP_sha256();
        unsigned int keyLen = 32;

        if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
            EVP_DigestUpdate(mdctx, passwordBytes.constData(), passwordBytes.size()) != 1 ||
            EVP_DigestFinal_ex(mdctx, key, &keyLen) != 1) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }
        EVP_MD_CTX_free(mdctx);

        // Используем EVP API для SHA1 для IV
        mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            std::cout << "Ошибка: Не удалось создать контекст EVP_MD" << std::endl;
            return false;
        }

        md = EVP_sha1();
        unsigned char hash[SHA_DIGEST_LENGTH];
        unsigned int hashLen = SHA_DIGEST_LENGTH;

        if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
            EVP_DigestUpdate(mdctx, passwordBytes.constData(), passwordBytes.size()) != 1 ||
            EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
            EVP_MD_CTX_free(mdctx);
            return false;
        }
        EVP_MD_CTX_free(mdctx);

        memcpy(iv, hash, 16);
        keyInitialized = true;

        // Безопасно очищаем пароль из памяти
        passwordBytes.fill(0);

        return true;
    }

    // Проверка, зашифрован ли файл
    bool isFileEncryptedInternal(const QString& filePath) const {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            return false;
        }

        unsigned char marker[MARKER_SIZE];
        qint64 bytesRead = file.read(reinterpret_cast<char*>(marker), MARKER_SIZE);
        file.close();

        if (bytesRead != MARKER_SIZE) {
            return false;
        }

        return memcmp(marker, ENCRYPTED_MARKER, MARKER_SIZE) == 0;
    }

public:
    // Запрещаем копирование и присваивание
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    // Статический метод для получения экземпляра
    static CryptoManager* getInstance() {
        if (instance == nullptr) {
            instance = new CryptoManager();
        }
        return instance;
    }

    // Деструктор
    ~CryptoManager() {
        // Безопасно очищаем ключи и IV из памяти
        secureZero(key, sizeof(key));
        secureZero(iv, sizeof(iv));
        keyInitialized = false;
    }

    // Метод для явного удаления экземпляра
    static void destroyInstance() {
        delete instance;
        instance = nullptr;
    }

    // Публичный метод для проверки, зашифрован ли файл
    static bool isFileEncrypted(const QString& filePath) {
        CryptoManager* cm = getInstance();
        return cm->isFileEncryptedInternal(filePath);
    }

    // Инициализация с паролем
    bool initialize(const QString& password) {
        return deriveKeyFromPassword(password);
    }

    // Шифрование файла
    bool encryptFile(const QString& inputPath, QString& outputPath) {
        if (!keyInitialized) {
            std::cout << "Ошибка: CryptoManager не инициализирован паролем" << std::endl;
            return false;
        }

        // Проверяем, не зашифрован ли уже файл
        if (isFileEncryptedInternal(inputPath)) {
            std::cout << "  Файл уже зашифрован, пропускаем: "
                      << QFileInfo(inputPath).fileName().toStdString() << std::endl;
            outputPath = inputPath;
            return true;
        }

        QFile inFile(inputPath);
        if (!inFile.open(QIODevice::ReadOnly)) {
            std::cout << "  Ошибка: Не удалось открыть файл для чтения: "
                      << inputPath.toStdString() << std::endl;
            return false;
        }

        // Временный файл для шифрования
        QString tempPath = inputPath + ".tmp";
        QFile outFile(tempPath);
        if (!outFile.open(QIODevice::WriteOnly)) {
            std::cout << "  Ошибка: Не удалось создать временный файл: "
                      << tempPath.toStdString() << std::endl;
            inFile.close();
            return false;
        }

        // Записываем маркер зашифрованного файла
        if (outFile.write(reinterpret_cast<const char*>(ENCRYPTED_MARKER), MARKER_SIZE) != MARKER_SIZE) {
            std::cout << "  Ошибка: Не удалось записать маркер" << std::endl;
            inFile.close();
            outFile.close();
            QFile::remove(tempPath);
            return false;
        }

        // Инициализация контекста шифрования
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cout << "  Ошибка: Не удалось создать контекст шифрования" << std::endl;
            inFile.close();
            outFile.close();
            QFile::remove(tempPath);
            return false;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            std::cout << "  Ошибка: Не удалось инициализировать шифрование" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            QFile::remove(tempPath);
            return false;
        }

        // Буферы для шифрования
        const int BUFFER_SIZE = 4096;
        std::vector<unsigned char> inBuffer(BUFFER_SIZE);
        std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

        int bytesRead, outLen;
        bool success = true;

        while ((bytesRead = inFile.read(reinterpret_cast<char*>(inBuffer.data()), BUFFER_SIZE)) > 0) {
            if (EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(), bytesRead) != 1) {
                success = false;
                break;
            }

            if (outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen) != outLen) {
                success = false;
                break;
            }
        }

        if (success && inFile.error() != QFile::NoError) {
            success = false;
        }

        if (success) {
            if (EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLen) != 1) {
                success = false;
            } else {
                if (outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen) != outLen) {
                    success = false;
                }
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();

        if (success) {
            // Заменяем оригинальный файл зашифрованным
            if (!QFile::remove(inputPath)) {
                std::cout << "  Ошибка: Не удалось удалить оригинальный файл" << std::endl;
                QFile::remove(tempPath);
                return false;
            }

            if (!QFile::rename(tempPath, inputPath)) {
                std::cout << "  Ошибка: Не удалось переименовать временный файл" << std::endl;
                QFile::remove(tempPath);
                return false;
            }

            outputPath = inputPath;
            std::cout << "  Файл успешно зашифрован" << std::endl;
        } else {
            QFile::remove(tempPath);
            std::cout << "  Ошибка при шифровании файла" << std::endl;
        }

        return success;
    }

    // Дешифрование файла
    bool decryptFile(const QString& inputPath, QString& outputPath) {
        if (!keyInitialized) {
            std::cout << "Ошибка: CryptoManager не инициализирован паролем" << std::endl;
            return false;
        }

        // Проверяем, зашифрован ли файл
        if (!isFileEncryptedInternal(inputPath)) {
            std::cout << "  Файл не зашифрован, пропускаем: "
                      << QFileInfo(inputPath).fileName().toStdString() << std::endl;
            outputPath = inputPath;
            return true;
        }

        QFile inFile(inputPath);
        if (!inFile.open(QIODevice::ReadOnly)) {
            std::cout << "  Ошибка: Не удалось открыть файл для чтения: "
                      << inputPath.toStdString() << std::endl;
            return false;
        }

        // Пропускаем маркер
        if (!inFile.seek(MARKER_SIZE)) {
            std::cout << "  Ошибка: Не удалось пропустить маркер" << std::endl;
            inFile.close();
            return false;
        }

        // Временный файл для дешифрования
        QString tempPath = inputPath + ".tmp";
        QFile outFile(tempPath);
        if (!outFile.open(QIODevice::WriteOnly)) {
            std::cout << "  Ошибка: Не удалось создать временный файл: "
                      << tempPath.toStdString() << std::endl;
            inFile.close();
            return false;
        }

        // Инициализация контекста дешифрования
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cout << "  Ошибка: Не удалось создать контекст дешифрования" << std::endl;
            inFile.close();
            outFile.close();
            QFile::remove(tempPath);
            return false;
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            std::cout << "  Ошибка: Не удалось инициализировать дешифрование" << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            inFile.close();
            outFile.close();
            QFile::remove(tempPath);
            return false;
        }

        // Буферы для дешифрования
        const int BUFFER_SIZE = 4096;
        std::vector<unsigned char> inBuffer(BUFFER_SIZE);
        std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);

        int bytesRead, outLen;
        bool success = true;

        while ((bytesRead = inFile.read(reinterpret_cast<char*>(inBuffer.data()), BUFFER_SIZE)) > 0) {
            if (EVP_DecryptUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(), bytesRead) != 1) {
                success = false;
                break;
            }

            if (outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen) != outLen) {
                success = false;
                break;
            }
        }

        if (success && inFile.error() != QFile::NoError) {
            success = false;
        }

        if (success) {
            if (EVP_DecryptFinal_ex(ctx, outBuffer.data(), &outLen) != 1) {
                success = false;
            } else {
                if (outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen) != outLen) {
                    success = false;
                }
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        inFile.close();
        outFile.close();

        if (success) {
            // Заменяем оригинальный файл расшифрованным
            if (!QFile::remove(inputPath)) {
                std::cout << "  Ошибка: Не удалось удалить оригинальный файл" << std::endl;
                QFile::remove(tempPath);
                return false;
            }

            if (!QFile::rename(tempPath, inputPath)) {
                std::cout << "  Ошибка: Не удалось переименовать временный файл" << std::endl;
                QFile::remove(tempPath);
                return false;
            }

            outputPath = inputPath;
            std::cout << "  Файл успешно расшифрован" << std::endl;
        } else {
            QFile::remove(tempPath);
            std::cout << "  Ошибка при дешифровании файла" << std::endl;
        }

        return success;
    }
};

// Инициализация статического члена
CryptoManager* CryptoManager::instance = nullptr;

// Рекурсивная функция для обхода папок и файлов с сбором информации
void collectFilesInfo(const QString &path, const QString &basePath, QList<FileInfo> &files, int depth = 0) {
    QDir dir(path);

    if (!dir.exists()) {
        std::cout << "Директория не существует: " << path.toStdString() << std::endl;
        return;
    }

    QFileInfoList entries = dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);
    std::string indent(depth * 2, ' ');

    for (const QFileInfo &entry : entries) {
        if (entry.isDir()) {
            std::cout << indent << "[ПАПКА] " << entry.fileName().toStdString() << std::endl;
            collectFilesInfo(entry.absoluteFilePath(), basePath, files, depth + 1);
        } else if (entry.isFile()) {
            QString relativePath = QDir(basePath).relativeFilePath(entry.absoluteFilePath());

            std::cout << indent << "[ФАЙЛ] " << entry.fileName().toStdString()
                      << " (" << entry.size() << " байт)" << std::endl;

            FileInfo fileInfo;
            fileInfo.path = entry.absoluteFilePath();
            fileInfo.relativePath = relativePath;
            fileInfo.size = entry.size();
            fileInfo.hash = QString();
            fileInfo.isEncrypted = CryptoManager::isFileEncrypted(entry.absoluteFilePath());

            if (fileInfo.isEncrypted) {
                std::cout << indent << "  [ЗАШИФРОВАН]" << std::endl;
            }

            files.append(fileInfo);
        }
    }
}

// Функция для поиска папки по имени
QString findFolder(const QString &folderName, const QString &startPath) {
    QDir currentDir(startPath);
    const int maxDepth = 5;
    int depth = 0;

    std::cout << "Поиск папки " << folderName.toStdString() << "..." << std::endl;

    while (!currentDir.exists(folderName) && depth < maxDepth) {
        std::cout << "  Проверяем: " << currentDir.absolutePath().toStdString() << std::endl;

        if (!currentDir.cdUp()) {
            break;
        }
        depth++;
    }

    if (currentDir.exists(folderName)) {
        QString foundPath = currentDir.absoluteFilePath(folderName);
        std::cout << "Папка " << folderName.toStdString() << " найдена: "
                  << foundPath.toStdString() << std::endl;
        return foundPath;
    }

    // Если не нашли вверх, ищем в поддиректориях
    QDir startDir(startPath);
    QFileInfoList dirs = startDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);

    for (const QFileInfo &dir : dirs) {
        if (dir.fileName() == folderName) {
            std::cout << "Папка " << folderName.toStdString() << " найдена в текущей директории"
                      << std::endl;
            return dir.absoluteFilePath();
        }
    }

    for (const QFileInfo &dir : dirs) {
        QDir subDir(dir.absoluteFilePath());
        QFileInfoList subDirs = subDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);

        for (const QFileInfo &subDirInfo : subDirs) {
            if (subDirInfo.fileName() == folderName) {
                std::cout << "Папка " << folderName.toStdString() << " найдена в поддиректории"
                          << std::endl;
                return subDirInfo.absoluteFilePath();
            }
        }
    }

    std::cout << "Папка " << folderName.toStdString() << " не найдена" << std::endl;
    return QString();
}

// Функция для вычисления SHA-256 хэша файла
QString calculateSHA256(const QString &filePath) {
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly)) {
        std::cout << "  Ошибка: Не удалось открыть файл для чтения: "
                  << filePath.toStdString() << std::endl;
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    const qint64 bufferSize = 8192;
    QByteArray buffer;
    buffer.resize(static_cast<int>(bufferSize));

    qint64 bytesRead;

    while ((bytesRead = file.read(buffer.data(), bufferSize)) > 0) {
        hash.addData(buffer.data(), bytesRead);
    }

    file.close();

    if (file.error() != QFile::NoError) {
        std::cout << "  Ошибка при чтении файла: " << file.errorString().toStdString() << std::endl;
        return QString();
    }

    return QString(hash.result().toHex());
}

// Функция для вычисления и вывода хэшей для всех файлов
void calculateAndPrintHashes(const QList<FileInfo> &files, const QString &stage) {
    std::cout << "=== ВЫЧИСЛЕНИЕ SHA-256 ХЭШЕЙ " << stage.toStdString() << " ===" << std::endl;
    std::cout << std::endl;

    for (int i = 0; i < files.size(); ++i) {
        std::cout << "Файл " << (i + 1) << " из " << files.size() << ": "
                  << files[i].relativePath.toStdString() << std::endl;

        QString hash = calculateSHA256(files[i].path);

        if (!hash.isEmpty()) {
            std::cout << "  SHA-256: " << hash.toStdString() << std::endl;
        } else {
            std::cout << "  Ошибка вычисления" << std::endl;
        }
        std::cout << std::endl;
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    // Устанавливаем кодировку консоли Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    QString currentPath = QFileInfo(QCoreApplication::applicationFilePath()).absolutePath();
    std::cout << "Текущая директория: " << currentPath.toStdString() << std::endl;
    std::cout << std::endl;

    // Ввод названия папки
    std::string folderName;
    std::cout << "Введите название папки для поиска: ";
    std::getline(std::cin, folderName);

    // Ввод пароля
    std::string password;
    std::cout << "Введите пароль для шифрования/дешифрования: ";
    std::getline(std::cin, password);

    // Выбор режима
    std::string mode;
    std::cout << "Выберите режим (1 - шифрование, 2 - дешифрование): ";
    std::getline(std::cin, mode);

    std::cout << std::endl;

    // Поиск папки
    QString folderPath = findFolder(QString::fromStdString(folderName), currentPath);

    if (folderPath.isEmpty()) {
        std::cout << "Папка не найдена. Программа завершена." << std::endl;
        return 0;
    }

    // Инициализация CryptoManager с паролем
    CryptoManager* crypto = CryptoManager::getInstance();
    if (!crypto->initialize(QString::fromStdString(password))) {
        std::cout << "Ошибка инициализации крипто-менеджера. Программа завершена." << std::endl;
        CryptoManager::destroyInstance();
        return 0;
    }

    // Безопасно очищаем пароль из памяти
    password.assign(password.size(), '0');

    std::cout << std::endl;
    std::cout << "Содержимое папки " << folderName << ":" << std::endl;
    std::cout << std::endl;

    // Собираем информацию о файлах
    QList<FileInfo> files;
    collectFilesInfo(folderPath, folderPath, files);

    std::cout << std::endl;
    std::cout << "Найдено файлов: " << files.size() << std::endl;
    std::cout << std::endl;

    if (files.isEmpty()) {
        std::cout << "В папке нет файлов для обработки." << std::endl;
        CryptoManager::destroyInstance();
        return 0;
    }

    // Выполняем шифрование или дешифрование
    if (mode == "1") {
        // При шифровании - сначала вычисляем хэши (эталонные)
        calculateAndPrintHashes(files, "ДО ШИФРОВАНИЯ");

        std::cout << "=== ШИФРОВАНИЕ ФАЙЛОВ ===" << std::endl;
        std::cout << std::endl;

        for (int i = 0; i < files.size(); ++i) {
            std::cout << "Файл " << (i + 1) << " из " << files.size() << ": "
                      << files[i].relativePath.toStdString() << std::endl;

            QString outputPath;
            if (crypto->encryptFile(files[i].path, outputPath)) {
                files[i].isEncrypted = true;
            }
            std::cout << std::endl;
        }

        std::cout << "Шифрование завершено. Сохраните выведенные выше хэши для последующей проверки." << std::endl;
    }
    else if (mode == "2") {
        std::cout << "=== ДЕШИФРОВАНИЕ ФАЙЛОВ ===" << std::endl;
        std::cout << std::endl;

        for (int i = 0; i < files.size(); ++i) {
            std::cout << "Файл " << (i + 1) << " из " << files.size() << ": "
                      << files[i].relativePath.toStdString() << std::endl;

            QString outputPath;
            if (crypto->decryptFile(files[i].path, outputPath)) {
                files[i].isEncrypted = false;
            }
            std::cout << std::endl;
        }

        // При дешифровании - после дешифрования вычисляем хэши для проверки целостности
        calculateAndPrintHashes(files, "ПОСЛЕ ДЕШИФРОВАНИЯ");

        std::cout << "Дешифрование завершено. Сравните эти хэши с хэшами, сохраненными до шифрования." << std::endl;
    }
    else {
        std::cout << "Неверный режим. Программа завершена." << std::endl;
        CryptoManager::destroyInstance();
        return 0;
    }

    std::cout << std::endl;
    std::cout << "Обработка завершена." << std::endl;

    // Явно уничтожаем экземпляр CryptoManager перед завершением программы
    CryptoManager::destroyInstance();

    return 0;
}
