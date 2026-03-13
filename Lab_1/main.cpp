#include <QCoreApplication>
#include <QFileInfo>
#include <windows.h>
#include <iostream>

#include "CryptoManager.h"
#include "FileUtils.h"
#include "FileInfo.h"
#include "Logger.h"

/**
 * @brief Главная функция программы
 *
 * Программа для шифрования/дешифрования всех файлов в указанной папке
 * с использованием AES-256-CBC. Пароль используется для генерации ключа.
 *
 * Этапы работы:
 * 1. Установка UTF-8 кодировки для консоли Windows
 * 2. Запрос пути к папке, пароля и режима работы
 * 3. Проверка существования папки
 * 4. Инициализация CryptoManager паролем
 * 5. Сбор информации о файлах
 * 6. В зависимости от режима:
 *    - Режим 1 (шифрование): шифрование файлов
 *    - Режим 2 (дешифрование): дешифрование файлов
 */
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    // Настройка консоли для корректного отображения UTF-8 (русские буквы)
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    /* // Закомментировано: старый код с поиском папки
    // Получаем путь к директории, где находится исполняемый файл
    QString currentPath =
        QFileInfo(QCoreApplication::applicationFilePath()).absolutePath();

    std::cout << "Текущая директория: "
              << currentPath.toStdString() << std::endl << std::endl;

    // Ввод имени папки для поиска
    std::string folderName;
    std::cout << "Введите название папки для поиска: ";
    std::getline(std::cin, folderName);
    */

    // Ввод пути к папке для обработки
    std::string folderPathInput;
    std::cout << "Введите полный путь к папке для обработки: ";
    std::getline(std::cin, folderPathInput);

    // Ввод пароля (будет использован для генерации ключа)
    std::string password;
    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);

    // Выбор режима: 1 - шифрование, 2 - дешифрование
    std::string mode;
    std::cout << "Выберите режим (1 - шифрование, 2 - дешифрование): ";
    std::getline(std::cin, mode);

    /* // Закомментировано: старый код с поиском папки
    // Поиск указанной папки
    QString folderPath =
        findFolder(QString::fromStdString(folderName), currentPath);
    */

    // Проверка существования указанной папки
    QString folderPath = QString::fromStdString(folderPathInput);
    QFileInfo folderInfo(folderPath);

    if (!folderInfo.exists() || !folderInfo.isDir()) {
        std::cout << "[ОШИБКА] Указанная папка не существует или не является директорией" << std::endl;

        // Пытаемся инициализировать логгер для записи ошибки
        QString appPath = QFileInfo(QCoreApplication::applicationFilePath()).absolutePath();
        Logger::initialize(appPath);
        Logger* logger = Logger::getInstance();
        if (logger) {
            logger->logError("Указанная папка не существует или не является директорией: " + folderPath);
            logger->notifyLogsUpdated();
        }
        Logger::destroyInstance();
        return 1;
    }

    // std::cout << "Папка найдена: " << folderPath.toStdString() << std::endl; // Закомментировано

    // Инициализация логгера
    QString appPath = QFileInfo(QCoreApplication::applicationFilePath()).absolutePath();
    Logger::initialize(appPath);
    Logger* logger = Logger::getInstance();

    // Инициализация крипто-менеджера паролем
    CryptoManager* crypto = CryptoManager::getInstance();
    if (!crypto->initialize(QString::fromStdString(password))) {
        std::cout << "[ОШИБКА] Ошибка инициализации крипто-менеджера" << std::endl;
        if (logger) {
            logger->logError("Ошибка инициализации крипто-менеджера");
            logger->notifyLogsUpdated();
        }
        CryptoManager::destroyInstance();
        Logger::destroyInstance();
        return 1;
    }

    // Затираем пароль в памяти после использования
    password.assign(password.size(), '0');

    // Сбор информации о всех файлах в папке
    QList<FileInfo> files;
    collectFilesInfo(folderPath, folderPath, files);

    if (files.isEmpty()) {
        std::cout << "В указанной папке нет файлов для обработки" << std::endl;
        if (logger) {
            logger->logInfo("В указанной папке нет файлов для обработки: " + folderPath);
            logger->notifyLogsUpdated();
        }
        CryptoManager::destroyInstance();
        Logger::destroyInstance();
        return 0;
    }

    std::cout << "Найдено файлов для обработки: " << files.size() << std::endl;

    int successCount = 0;
    int skippedCount = 0;
    int errorCount = 0;
    QString operation;

    // Выполнение операции в зависимости от режима
    if (mode == "1") {
        operation = "шифрования";
        std::cout << "Начинаю шифрование файлов..." << std::endl;

        // Режим шифрования
        // calculateAndPrintHashes(files, "ДО ШИФРОВАНИЯ"); // Закомментировано

        for (auto &file : files) {
            QString outputPath;

            // Проверяем статус ДО операции
            bool wasEncrypted = CryptoManager::isFileEncrypted(file.path);
            bool result = crypto->encryptFile(file.path, outputPath);

            if (result) {
                if (wasEncrypted) {
                    // Файл уже был зашифрован до операции
                    skippedCount++;
                } else {
                    // Файл был успешно зашифрован сейчас
                    successCount++;
                }
            } else {
                errorCount++;
            }
        }

        std::cout << "Шифрование завершено." << std::endl;

        // Уведомляем об обновлении лог-файлов
        if (logger) {
            logger->notifyLogsUpdated();
        }
    }
    else if (mode == "2") {
        operation = "дешифрования";
        std::cout << "Начинаю дешифрование файлов..." << std::endl;

        // Режим дешифрования
        for (auto &file : files) {
            QString outputPath;

            // Проверяем статус ДО операции
            bool wasEncrypted = CryptoManager::isFileEncrypted(file.path);
            bool result = crypto->decryptFile(file.path, outputPath);

            if (result) {
                if (!wasEncrypted) {
                    // Файл уже был расшифрован до операции
                    skippedCount++;
                } else {
                    // Файл был успешно расшифрован сейчас
                    successCount++;
                }
            } else {
                errorCount++;
            }
        }

        // После дешифрования вычисляем хэши для проверки целостности
        // calculateAndPrintHashes(files, "ПОСЛЕ ДЕШИФРОВАНИЯ"); // Закомментировано

        std::cout << "Дешифрование завершено." << std::endl;

        // Уведомляем об обновлении лог-файлов
        if (logger) {
            logger->notifyLogsUpdated();
        }
    }
    else {
        std::cout << "[ОШИБКА] Неверный режим работы. Используйте 1 для шифрования или 2 для дешифрования" << std::endl;
        if (logger) {
            logger->logError("Неверный режим работы: " + QString::fromStdString(mode));
        }
        errorCount++;
    }

    // Вывод статистики в консоль
    std::cout << "Статистика: обработано " << (successCount + skippedCount + errorCount)
              << " файлов (успешно: " << successCount
              << ", пропущено: " << skippedCount
              << ", ошибок: " << errorCount << ")" << std::endl;

    // Записываем итоговую статистику в информационный лог (только если была выбрана корректная операция)
    if (logger && (mode == "1" || mode == "2")) {
        QString summary = QString("Итого по операции %1: Успешно: %2, Пропущено: %3, Ошибок: %4")
                              .arg(operation).arg(successCount).arg(skippedCount).arg(errorCount);
        logger->logInfo(summary);

        // Уведомляем об обновлении лог-файлов
        logger->notifyLogsUpdated();
    }

    // Очистка ресурсов
    CryptoManager::destroyInstance();
    Logger::destroyInstance();

    return (errorCount > 0) ? 1 : 0;
}
