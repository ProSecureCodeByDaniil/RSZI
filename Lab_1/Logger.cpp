/**
 * @file Logger.cpp
 * Реализация логгера. Все сообщения пишутся в файлы с временной меткой.
 * Используется мьютекс для потокобезопасности.
 */

#include "Logger.h"
#include <QCoreApplication>
#include <QDir>

Logger* Logger::instance = nullptr;
QMutex Logger::mutex;

// Конструктор: открываем 4 файла в режиме добавления (append)
Logger::Logger(const QString& appDirPath)
    : logDir(appDirPath)
{
    QString encryptPath = logDir + "/logs_encrypt.txt";
    QString decryptPath = logDir + "/logs_decrypt.txt";
    QString errorPath = logDir + "/logs_errors.txt";
    QString infoPath = logDir + "/logs_info.txt";

    encryptLogFile.setFileName(encryptPath);
    decryptLogFile.setFileName(decryptPath);
    errorLogFile.setFileName(errorPath);
    infoLogFile.setFileName(infoPath);

    encryptLogFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text);
    decryptLogFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text);
    errorLogFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text);
    infoLogFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text);
}

Logger::~Logger()
{
    if (encryptLogFile.isOpen()) encryptLogFile.close();
    if (decryptLogFile.isOpen()) decryptLogFile.close();
    if (errorLogFile.isOpen()) errorLogFile.close();
    if (infoLogFile.isOpen()) infoLogFile.close();
}

void Logger::initialize(const QString& appDirPath)
{
    QMutexLocker locker(&mutex);
    if (!instance) {
        instance = new Logger(appDirPath);
    }
}

Logger* Logger::getInstance()
{
    QMutexLocker locker(&mutex);
    return instance;
}

void Logger::destroyInstance()
{
    QMutexLocker locker(&mutex);
    delete instance;
    instance = nullptr;
}

// Вспомогательная запись с UTF-8
void Logger::writeToFile(QFile& file, const QString& message)
{
    if (file.isOpen()) {
        QByteArray utf8Data = message.toUtf8();
        file.write(utf8Data);
        file.write("\n");
        file.flush();
    }
}

void Logger::logEncrypt(const QString& message)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ШИФРОВАНИЕ] " + message;
    writeToFile(encryptLogFile, formattedMessage);
}

void Logger::logDecrypt(const QString& message)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ДЕШИФРОВАНИЕ] " + message;
    writeToFile(decryptLogFile, formattedMessage);
}

void Logger::logError(const QString& message, const QString& fileName)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ОШИБКА] " + message;
    if (!fileName.isEmpty()) {
        formattedMessage += " (файл: " + fileName + ")";
    }
    writeToFile(errorLogFile, formattedMessage);
}

void Logger::logInfo(const QString& message)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ИНФО] " + message;
    writeToFile(infoLogFile, formattedMessage);
}

void Logger::logSkipped(const QString& message, const QString& fileName, LogOperation operation)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ПРОПУЩЕН] " + message + " (файл: " + fileName + ")";

    if (operation == LogOperation::Encrypt) {
        writeToFile(encryptLogFile, formattedMessage);
    } else if (operation == LogOperation::Decrypt) {
        writeToFile(decryptLogFile, formattedMessage);
    }
    // Если Unknown — не пишем никуда (только для совместимости)
}
