#ifndef FILEINFO_H
#define FILEINFO_H

#include <QString>

struct FileInfo {
    QString path;
    QString relativePath;
    QString hash;
    qint64 size;
    bool isEncrypted;
};

#endif // FILEINFO_H
