#include "FileUtils.h"
#include "CryptoManager.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>
// #include <iostream> // Закомментировано: убираем лишний вывод

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
        // std::cout << "Директория не существует: " // Закомментировано
        //           << path.toStdString() << std::endl;
        return;
    }

    // Получаем список всех элементов (папки и файлы, исключая . и ..)
    QFileInfoList entries =
        dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);

    // std::string indent(depth * 2, ' ');  // Отступ для визуализации дерева // Закомментировано

    for (const QFileInfo &entry : entries) {

        if (entry.isDir()) {
            // Обработка папки - рекурсивный вызов
            // std::cout << indent << "[ПАПКА] " // Закомментировано
            //           << entry.fileName().toStdString() << std::endl;

            collectFilesInfo(entry.absoluteFilePath(),
                             basePath,
                             files,
                             depth + 1);
        }
        else if (entry.isFile()) {
            // Обработка файла - сохранение информации
            QString relativePath =
                QDir(basePath).relativeFilePath(entry.absoluteFilePath());

            // std::cout << indent << "[ФАЙЛ] " // Закомментировано
            //           << entry.fileName().toStdString()
            //           << " (" << entry.size() << " байт)"
            //           << std::endl;

            FileInfo fileInfo;
            fileInfo.path = entry.absoluteFilePath();
            fileInfo.relativePath = relativePath;
            fileInfo.size = entry.size();
            fileInfo.hash = QString();  // Хэш будет вычислен позже
            fileInfo.isEncrypted =
                CryptoManager::isFileEncrypted(entry.absoluteFilePath());

            /* // Закомментировано
            if (fileInfo.isEncrypted) {
                std::cout << indent << "  [ЗАШИФРОВАН]" << std::endl;
            }
            */

            files.append(fileInfo);
        }
    }
}

/* // Закомментировано: функция поиска папки больше не используется
QString findFolder(const QString &folderName,
                   const QString &startPath)
{
    QDir currentDir(startPath);
    const int maxDepth = 5;  // Максимальная глубина подъёма вверх
    int depth = 0;

    std::cout << "Поиск папки "
              << folderName.toStdString()
              << "..." << std::endl;

    // Поиск вверх по иерархии
    while (!currentDir.exists(folderName) && depth < maxDepth) {

        std::cout << "  Проверяем: "
                  << currentDir.absolutePath().toStdString()
                  << std::endl;

        if (!currentDir.cdUp())  // Поднимаемся на уровень выше
            break;

        depth++;
    }

    // Если нашли подъёмом вверх
    if (currentDir.exists(folderName)) {
        QString foundPath =
            currentDir.absoluteFilePath(folderName);

        std::cout << "Папка найдена: "
                  << foundPath.toStdString()
                  << std::endl;

        return foundPath;
    }

    // Поиск в текущей директории
    QDir startDir(startPath);
    QFileInfoList dirs =
        startDir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);

    for (const QFileInfo &dir : dirs) {
        if (dir.fileName() == folderName)
            return dir.absoluteFilePath();
    }

    // Поиск во вложенных папках (одна глубина)
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
*/

/**
 * @brief Вычисление SHA-256 хэша файла
 * @param filePath Путь к файлу
 * @return Хэш в hex или пустая строка
 */
QString calculateSHA256(const QString &filePath)
{
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly)) {
        // std::cout << "Ошибка открытия файла: " // Закомментировано
        //           << filePath.toStdString() << std::endl;
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);

    const qint64 bufferSize = 8192;  // 8 КБ буфер для чтения
    QByteArray buffer;
    buffer.resize(static_cast<int>(bufferSize));

    qint64 bytesRead;

    // Читаем файл блоками и обновляем хэш
    while ((bytesRead =
            file.read(buffer.data(), bufferSize)) > 0) {
        hash.addData(buffer.data(), bytesRead);
    }

    file.close();

    if (file.error() != QFile::NoError)
        return QString();

    return QString(hash.result().toHex());  // Конвертируем в hex-строку
}

/**
 * @brief Вывод хэшей всех файлов из списка
 * @param files Список файлов
 * @param stage Название этапа (для заголовка)
 */
void calculateAndPrintHashes(const QList<FileInfo> &files,
                             const QString &stage)
{
    /* // Закомментировано: убираем вывод хэшей
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
    */
}
