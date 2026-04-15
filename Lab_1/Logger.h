/**
 * @file Logger.h
 * @brief Модуль логирования (синглтон)
 *
 * Пишет в 4 файла:
 * - logs_encrypt.txt   (успешное шифрование и пропуски при шифровании)
 * - logs_decrypt.txt   (успешное дешифрование и пропуски при дешифровании)
 * - logs_errors.txt    (все ошибки)
 * - logs_info.txt      (общая информация и статистика)
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <QString>
#include <QFile>
#include <QTextStream>
#include <QMutex>
#include <QDateTime>

/**
 * @enum LogOperation
 * @brief Для различения операции при логировании пропущенных файлов
 */
enum class LogOperation {
    Encrypt,    ///< Операция шифрования
    Decrypt,    ///< Операция дешифрования
    Unknown     ///< Неизвестно (не пишется)
};

/**
 * @class Logger
 * @brief Синглтон для потокобезопасной записи в файлы логов
 */
class Logger {
private:
    static Logger* instance;
    static QMutex mutex;

    QString logDir;
    QFile encryptLogFile;
    QFile decryptLogFile;
    QFile errorLogFile;
    QFile infoLogFile;

    explicit Logger(const QString& appDirPath);
    ~Logger();

    void writeToFile(QFile& file, const QString& message);

public:
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    /**
     * @brief Инициализация (вызвать один раз в main)
     * @param appDirPath Путь к папке приложения (куда класть логи)
     */
    static void initialize(const QString& appDirPath);

    /**
     * @brief Получить экземпляр
     * @return указатель на Logger
     */
    static Logger* getInstance();

    /**
     * @brief Уничтожить экземпляр (при завершении)
     */
    static void destroyInstance();

    /**
     * @brief Записать успешное шифрование
     * @param message текст
     */
    void logEncrypt(const QString& message);

    /**
     * @brief Записать успешное дешифрование
     * @param message текст
     */
    void logDecrypt(const QString& message);

    /**
     * @brief Записать ошибку
     * @param message текст
     * @param fileName имя файла (опционально)
     */
    void logError(const QString& message, const QString& fileName = QString());

    /**
     * @brief Записать информационное сообщение
     * @param message текст
     */
    void logInfo(const QString& message);

    /**
     * @brief Записать пропуск файла (уже зашифрован или не зашифрован)
     * @param message причина
     * @param fileName имя файла
     * @param operation тип операции
     */
    void logSkipped(const QString& message, const QString& fileName, LogOperation operation = LogOperation::Unknown);
};

#endif // LOGGER_H
