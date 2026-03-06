#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <QString>
#include <QList>
#include "FileInfo.h"

void collectFilesInfo(const QString &path,
                      const QString &basePath,
                      QList<FileInfo> &files,
                      int depth = 0);

QString findFolder(const QString &folderName,
                   const QString &startPath);

QString calculateSHA256(const QString &filePath);

void calculateAndPrintHashes(const QList<FileInfo> &files,
                             const QString &stage);

#endif // FILEUTILS_H
