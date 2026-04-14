#include "FileUtils.h"
#include "CryptoManager.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>

/**
 * @brief Рекурсивный сбор информации о файлах
 * @param path Текущая директория
 * @param basePath Базовая директория (для относительных путей)
 * @param files Список для заполнения
 * @param depth Текущая глубина (для форматирования вывода)
 */
void collectFilesInfo(const QString &path,
                      const QString &basePath,
                      QList<FileInfo> &files,
                      int depth)
{
    QDir dir(path);

    if (!dir.exists()) {
        return;
    }

    // Получаем список всех элементов (папки и файлы, исключая . и ..)
    QFileInfoList entries =
        dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);

    for (const QFileInfo &entry : entries) {

        if (entry.isDir()) {
            // Обработка папки - рекурсивный вызов
            collectFilesInfo(entry.absoluteFilePath(),
                             basePath,
                             files,
                             depth + 1);
        }
        else if (entry.isFile()) {
            // Обработка файла - сохранение информации
            QString relativePath =
                QDir(basePath).relativeFilePath(entry.absoluteFilePath());

            FileInfo fileInfo;
            fileInfo.path = entry.absoluteFilePath();
            fileInfo.relativePath = relativePath;
            fileInfo.size = entry.size();
            fileInfo.hash = QString();  // Хэш будет вычислен позже
            fileInfo.isEncrypted =
                CryptoManager::isFileEncrypted(entry.absoluteFilePath());

            files.append(fileInfo);
        }
    }
}
