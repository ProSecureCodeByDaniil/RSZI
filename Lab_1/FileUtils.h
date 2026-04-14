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

#endif // FILEUTILS_H
