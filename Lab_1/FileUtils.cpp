#include "FileUtils.h"
#include "CryptoManager.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>
#include <iostream>

void collectFilesInfo(const QString &path,
                      const QString &basePath,
                      QList<FileInfo> &files,
                      int depth)
{
    QDir dir(path);

    if (!dir.exists()) {
        std::cout << "Директория не существует: "
                  << path.toStdString() << std::endl;
        return;
    }

    QFileInfoList entries =
        dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);

    std::string indent(depth * 2, ' ');

    for (const QFileInfo &entry : entries) {

        if (entry.isDir()) {
            std::cout << indent << "[ПАПКА] "
                      << entry.fileName().toStdString() << std::endl;

            collectFilesInfo(entry.absoluteFilePath(),
                             basePath,
                             files,
                             depth + 1);
        }
        else if (entry.isFile()) {

            QString relativePath =
                QDir(basePath).relativeFilePath(entry.absoluteFilePath());

            std::cout << indent << "[ФАЙЛ] "
                      << entry.fileName().toStdString()
                      << " (" << entry.size() << " байт)"
                      << std::endl;

            FileInfo fileInfo;
            fileInfo.path = entry.absoluteFilePath();
            fileInfo.relativePath = relativePath;
            fileInfo.size = entry.size();
            fileInfo.hash = QString();
            fileInfo.isEncrypted =
                CryptoManager::isFileEncrypted(entry.absoluteFilePath());

            if (fileInfo.isEncrypted) {
                std::cout << indent << "  [ЗАШИФРОВАН]" << std::endl;
            }

            files.append(fileInfo);
        }
    }
}

QString findFolder(const QString &folderName,
                   const QString &startPath)
{
    QDir currentDir(startPath);
    const int maxDepth = 5;
    int depth = 0;

    std::cout << "Поиск папки "
              << folderName.toStdString()
              << "..." << std::endl;

    while (!currentDir.exists(folderName) && depth < maxDepth) {

        std::cout << "  Проверяем: "
                  << currentDir.absolutePath().toStdString()
                  << std::endl;

        if (!currentDir.cdUp())
            break;

        depth++;
    }

    if (currentDir.exists(folderName)) {
        QString foundPath =
            currentDir.absoluteFilePath(folderName);

        std::cout << "Папка найдена: "
                  << foundPath.toStdString()
                  << std::endl;

        return foundPath;
    }

    QDir startDir(startPath);
    QFileInfoList dirs =
        startDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);

    for (const QFileInfo &dir : dirs) {
        if (dir.fileName() == folderName)
            return dir.absoluteFilePath();
    }

    for (const QFileInfo &dir : dirs) {
        QDir subDir(dir.absoluteFilePath());
        QFileInfoList subDirs =
            subDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);

        for (const QFileInfo &subDirInfo : subDirs) {
            if (subDirInfo.fileName() == folderName)
                return subDirInfo.absoluteFilePath();
        }
    }

    std::cout << "Папка не найдена" << std::endl;
    return QString();
}

QString calculateSHA256(const QString &filePath)
{
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly)) {
        std::cout << "Ошибка открытия файла: "
                  << filePath.toStdString() << std::endl;
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);

    const qint64 bufferSize = 8192;
    QByteArray buffer;
    buffer.resize(static_cast<int>(bufferSize));

    qint64 bytesRead;

    while ((bytesRead =
            file.read(buffer.data(), bufferSize)) > 0) {
        hash.addData(buffer.data(), bytesRead);
    }

    file.close();

    if (file.error() != QFile::NoError)
        return QString();

    return QString(hash.result().toHex());
}

void calculateAndPrintHashes(const QList<FileInfo> &files,
                             const QString &stage)
{
    std::cout << "=== ВЫЧИСЛЕНИЕ SHA-256 ХЭШЕЙ "
              << stage.toStdString()
              << " ==="
              << std::endl << std::endl;

    for (int i = 0; i < files.size(); ++i) {

        std::cout << "Файл "
                  << (i + 1)
                  << " из "
                  << files.size()
                  << ": "
                  << files[i].relativePath.toStdString()
                  << std::endl;

        QString hash =
            calculateSHA256(files[i].path);

        if (!hash.isEmpty())
            std::cout << "  SHA-256: "
                      << hash.toStdString()
                      << std::endl;
        else
            std::cout << "  Ошибка вычисления"
                      << std::endl;

        std::cout << std::endl;
    }
}
