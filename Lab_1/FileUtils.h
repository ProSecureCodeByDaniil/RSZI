#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <QString>
#include <QList>
#include "FileInfo.h"

/**
 * @brief Рекурсивный сбор информации о файлах в директории
 * @param path Текущий путь для обхода
 * @param basePath Базовый путь (для вычисления относительных путей)
 * @param files Список для заполнения структурами FileInfo
 * @param depth Текущая глубина рекурсии (для отступов в выводе)
 *
 * Функция выводит дерево папок и файлов в консоль.
 * Для каждого файла проверяется, зашифрован ли он.
 */
void collectFilesInfo(const QString &path,
                      const QString &basePath,
                      QList<FileInfo> &files,
                      int depth = 0);

/**
 * @brief Поиск папки по имени
 * @param folderName Имя искомой папки
 * @param startPath Начальный путь для поиска
 * @return Полный путь к найденной папке или пустая строка
 *
 * Алгоритм:
 * 1. Поднимается вверх до 5 уровней, проверяя наличие папки
 * 2. Ищет в текущей директории
 * 3. Ищет во вложенных папках текущей директории
 */
QString findFolder(const QString &folderName,
                   const QString &startPath);

/**
 * @brief Вычисление SHA-256 хэша файла
 * @param filePath Путь к файлу
 * @return Хэш в виде hex-строки или пустая строка при ошибке
 *
 * Использует QCryptographicHash с буфером 8 КБ для экономии памяти.
 */
QString calculateSHA256(const QString &filePath);

/**
 * @brief Вычисление и вывод хэшей для списка файлов
 * @param files Список файлов
 * @param stage Описание этапа (например "ДО ШИФРОВАНИЯ")
 *
 * Для каждого файла вычисляет SHA-256 и выводит в консоль.
 */
void calculateAndPrintHashes(const QList<FileInfo> &files,
                             const QString &stage);

#endif // FILEUTILS_H
