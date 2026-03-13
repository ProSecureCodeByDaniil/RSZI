#include "Logger.h"
#include <QCoreApplication>
#include <QDir>
#include <QTextCodec>
#include <iostream>

// Инициализация статических членов
Logger* Logger::instance = nullptr;
QMutex Logger::mutex;

/**
 * @brief Конструктор: открывает файлы логов для записи
 * @param appDirPath Путь к директории приложения
 */
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

    // Открываем файлы в режиме добавления (append) с UTF-8
    if (encryptLogFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        // Устанавливаем кодировку UTF-8 для потока
    }

    if (decryptLogFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        // Устанавливаем кодировку UTF-8 для потока
    }

    if (errorLogFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        // Устанавливаем кодировку UTF-8 для потока
    }

    if (infoLogFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        // Устанавливаем кодировку UTF-8 для потока
    }
}

/**
 * @brief Деструктор: закрывает файлы логов
 */
Logger::~Logger()
{
    if (encryptLogFile.isOpen())
        encryptLogFile.close();

    if (decryptLogFile.isOpen())
        decryptLogFile.close();

    if (errorLogFile.isOpen())
        errorLogFile.close();

    if (infoLogFile.isOpen())
        infoLogFile.close();
}

/**
 * @brief Инициализация логгера
 * @param appDirPath Путь к директории приложения
 */
void Logger::initialize(const QString& appDirPath)
{
    QMutexLocker locker(&mutex);
    if (!instance) {
        instance = new Logger(appDirPath);
    }
}

/**
 * @brief Получение экземпляра логгера
 */
Logger* Logger::getInstance()
{
    QMutexLocker locker(&mutex);
    return instance;
}

/**
 * @brief Уничтожение экземпляра логгера
 */
void Logger::destroyInstance()
{
    QMutexLocker locker(&mutex);
    delete instance;
    instance = nullptr;
}

/**
 * @brief Вспомогательный метод для записи с UTF-8
 */
void Logger::writeToFile(QFile& file, const QString& message)
{
    if (file.isOpen()) {
        // Явно указываем UTF-8 кодировку
        QByteArray utf8Data = message.toUtf8();
        file.write(utf8Data);
        file.write("\n");
        file.flush();
    }
}

/**
 * @brief Запись в лог шифрования
 * @param message Сообщение для записи
 */
void Logger::logEncrypt(const QString& message)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ШИФРОВАНИЕ] " + message;
    writeToFile(encryptLogFile, formattedMessage);
}

/**
 * @brief Запись в лог дешифрования
 * @param message Сообщение для записи
 */
void Logger::logDecrypt(const QString& message)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ДЕШИФРОВАНИЕ] " + message;
    writeToFile(decryptLogFile, formattedMessage);
}

/**
 * @brief Запись ошибки в лог
 * @param message Сообщение об ошибке
 * @param fileName Имя файла, в котором произошла ошибка (опционально)
 */
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

/**
 * @brief Запись информационного сообщения
 * @param message Информационное сообщение
 */
void Logger::logInfo(const QString& message)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ИНФО] " + message;
    writeToFile(infoLogFile, formattedMessage);
}

/**
 * @brief Запись информации о пропущенном файле (уже зашифрован/дешифрован)
 * @param message Информационное сообщение
 * @param fileName Имя файла
 * @param operation Тип операции (шифрование/дешифрование)
 */
void Logger::logSkipped(const QString& message, const QString& fileName, LogOperation operation)
{
    QMutexLocker locker(&mutex);
    QString formattedMessage = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") +
                               " - [ПРОПУЩЕН] " + message + " (файл: " + fileName + ")";

    // Если операция явно указана, используем её
    if (operation == LogOperation::Encrypt) {
        writeToFile(encryptLogFile, formattedMessage);
        return;
    } else if (operation == LogOperation::Decrypt) {
        writeToFile(decryptLogFile, formattedMessage);
        return;
    }

    // Иначе определяем по содержимому сообщения (для обратной совместимости)
    // Сначала проверяем специфичные фразы для дешифрования
    if (message.contains("не зашифрован", Qt::CaseInsensitive)) {
        // Для сообщений о дешифровании (файл не зашифрован)
        writeToFile(decryptLogFile, formattedMessage);
    } else if (message.contains("расшифрован", Qt::CaseInsensitive)) {
        // Для сообщений о дешифровании (уже расшифрован)
        writeToFile(decryptLogFile, formattedMessage);
    } else if (message.contains("зашифрован", Qt::CaseInsensitive) &&
               !message.contains("расшифрован", Qt::CaseInsensitive)) {
        // Для сообщений о шифровании (уже зашифрован)
        writeToFile(encryptLogFile, formattedMessage);
    } else if (message.contains("системным или защищенным", Qt::CaseInsensitive)) {
        // Для сообщений о системных/защищенных файлах - по умолчанию в encrypt
        // Но лучше всегда передавать operation при вызове
        writeToFile(encryptLogFile, formattedMessage);
    }
    // Больше не записываем в info лог
}

/**
 * @brief Сообщение о том, что лог-файлы обновлены
 */
void Logger::notifyLogsUpdated()
{
    std::cout << "Лог-файлы обновлены" << std::endl;
}
