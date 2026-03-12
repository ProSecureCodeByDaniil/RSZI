#include <QCoreApplication>
#include <QFileInfo>
#include <windows.h>
#include <iostream>

#include "CryptoManager.h"
#include "FileUtils.h"
#include "FileInfo.h"

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
 *    - Режим 1 (шифрование): вычисление хэшей ДО, шифрование файлов
 *    - Режим 2 (дешифрование): дешифрование файлов, вычисление хэшей ПОСЛЕ
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
        std::cout << "Указанная папка не существует или не является директорией." << std::endl;
        return 0;
    }

    std::cout << "Папка найдена: " << folderPath.toStdString() << std::endl;

    // Инициализация крипто-менеджера паролем
    CryptoManager* crypto = CryptoManager::getInstance();
    if (!crypto->initialize(QString::fromStdString(password))) {
        std::cout << "Ошибка инициализации." << std::endl;
        CryptoManager::destroyInstance();
        return 0;
    }

    // Затираем пароль в памяти после использования
    password.assign(password.size(), '0');

    // Сбор информации о всех файлах в папке
    QList<FileInfo> files;
    collectFilesInfo(folderPath, folderPath, files);

    // Выполнение операции в зависимости от режима
    if (mode == "1") {
        // Режим шифрования
        calculateAndPrintHashes(files, "ДО ШИФРОВАНИЯ");

        // Шифруем каждый файл
        for (auto &file : files) {
            QString outputPath;
            crypto->encryptFile(file.path, outputPath);
        }
    }
    else if (mode == "2") {
        // Режим дешифрования
        // Дешифруем каждый файл
        for (auto &file : files) {
            QString outputPath;
            crypto->decryptFile(file.path, outputPath);
        }

        // После дешифрования вычисляем хэши для проверки целостности
        calculateAndPrintHashes(files, "ПОСЛЕ ДЕШИФРОВАНИЯ");
    }

    // Очистка ресурсов
    CryptoManager::destroyInstance();
    return 0;
}
