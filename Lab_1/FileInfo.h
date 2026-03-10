#ifndef FILEINFO_H
#define FILEINFO_H

#include <QString>

/**
 * @struct FileInfo
 * @brief Структура для хранения информации о файле при обходе директорий
 */
struct FileInfo {
    QString path;            ///< Полный абсолютный путь к файлу
    QString relativePath;    ///< Относительный путь от базовой директории
    QString hash;            ///< SHA-256 хэш файла (может быть пустым)
    qint64 size;             ///< Размер файла в байтах
    bool isEncrypted;        ///< Флаг: true если файл зашифрован (содержит маркер)
};

#endif // FILEINFO_H
