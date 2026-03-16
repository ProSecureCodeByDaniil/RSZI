#ifndef LOGGER_H
#define LOGGER_H

#include <QString>
#include <QFile>
#include <QTextStream>
#include <QMutex>
#include <QDateTime>

/**
 * @enum LogOperation
 * @brief Тип операции для логирования
 */
enum class LogOperation {
    Encrypt,    ///< Операция шифрования
    Decrypt,    ///< Операция дешифрования
    Unknown     ///< Неизвестная операция (для обратной совместимости)
};

/**
 * @class Logger
 * @brief Класс для логирования операций шифрования/дешифрования в файлы
 *
 * Создает файлы logs_encrypt.txt и logs_decrypt.txt рядом с исполняемым файлом
 * и записывает в них информацию о выполненных операциях.
 */
class Logger {
private:
    static Logger* instance;    ///< Указатель на единственный экземпляр (синглтон)
    static QMutex mutex;        ///< Мьютекс для потокобезопасности

    QString logDir;             ///< Директория для лог-файлов
    QFile encryptLogFile;       ///< Файл для логов шифрования
    QFile decryptLogFile;       ///< Файл для логов дешифрования
    QFile errorLogFile;         ///< Файл для логов ошибок
    QFile infoLogFile;          ///< Файл для информационных логов

    /**
     * @brief Приватный конструктор (синглтон)
     * @param appDirPath Путь к директории приложения
     */
    explicit Logger(const QString& appDirPath);

    /**
     * @brief Приватный деструктор
     */
    ~Logger();

    /**
     * @brief Вспомогательный метод для записи с UTF-8
     * @param file Ссылка на файл для записи
     * @param message Сообщение для записи
     */
    void writeToFile(QFile& file, const QString& message);

public:
    // Запрет копирования и присваивания
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    /**
     * @brief Инициализация логгера (должна быть вызвана перед использованием)
     * @param appDirPath Путь к директории приложения
     */
    static void initialize(const QString& appDirPath);

    /**
     * @brief Получение экземпляра логгера
     * @return Указатель на единственный экземпляр Logger
     */
    static Logger* getInstance();

    /**
     * @brief Уничтожение экземпляра логгера
     */
    static void destroyInstance();

    /**
     * @brief Запись в лог шифрования
     * @param message Сообщение для записи
     */
    void logEncrypt(const QString& message);

    /**
     * @brief Запись в лог дешифрования
     * @param message Сообщение для записи
     */
    void logDecrypt(const QString& message);

    /**
     * @brief Запись ошибки в лог
     * @param message Сообщение об ошибке
     * @param fileName Имя файла, в котором произошла ошибка (опционально)
     */
    void logError(const QString& message, const QString& fileName = QString());

    /**
     * @brief Запись информационного сообщения
     * @param message Информационное сообщение
     */
    void logInfo(const QString& message);

    /**
     * @brief Запись информации о пропущенном файле (уже зашифрован/дешифрован)
     * @param message Информационное сообщение
     * @param fileName Имя файла
     * @param operation Тип операции (шифрование/дешифрование)
     */
    void logSkipped(const QString& message, const QString& fileName, LogOperation operation = LogOperation::Unknown);

    /**
     * @brief Сообщение о том, что лог-файлы обновлены (выводится в консоль один раз)
     */
    void notifyLogsUpdated();
};

#endif // LOGGER_H
