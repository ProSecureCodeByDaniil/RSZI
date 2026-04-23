/**
 * @file main.cpp
 * @brief Точка входа в консольное приложение
 *
 * Запрашивает у пользователя:
 * - путь к папке
 * - пароль
 * - режим (1 - шифрование, 2 - дешифрование)
 *
 * Инициализирует логгер и криптоменеджер, запускает обработку.
 * Пароль затирается из памяти после использования.
 */

#include <QCoreApplication>
#include <QFileInfo>
#include <iostream>
#include <string>
#include <cstring>

#include "CryptoManager.h"
#include "Logger.h"

#ifdef _WIN32
#include <windows.h>
#endif

/**
 * @brief Безопасно очищает строку с паролем (защита от оптимизации)
 * @param str строка, которую нужно затереть
 */
void secureStringClear(std::string& str)
{
    if (str.empty())
        return;

    // Затираем через volatile, чтобы компилятор не выкинул код
    volatile char* pwdPtr = &str[0];
    for (size_t i = 0; i < str.size(); ++i) {
        pwdPtr[i] = 0;
    }

    // Дополнительная очистка внутреннего буфера
    str.assign(str.size(), '\0');
    str.clear();
    str.shrink_to_fit();
}

/**
 * @brief Главная функция
 * @param argc количество аргументов
 * @param argv массив аргументов (не используются)
 * @return 0 при успехе, 1 при ошибке
 */
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

// На Windows — UTF-8 в консоли, чтобы русские буквы не ломались
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    // ----- Ввод данных от пользователя -----
    std::string folderPathInput;
    std::cout << "Введите полный путь к папке для обработки: ";
    std::getline(std::cin, folderPathInput);

    std::string password;
    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);

    std::string modeInput;
    std::cout << "Выберите режим (1 - шифрование, 2 - дешифрование): ";
    std::getline(std::cin, modeInput);

    OperationMode mode;
    if (modeInput == "1") {
        mode = OperationMode::Encrypt;
    } else if (modeInput == "2") {
        mode = OperationMode::Decrypt;
    } else {
        std::cout << "[ОШИБКА] Неверный режим работы. Используйте 1 или 2" << std::endl;
        return 1;
    }

    // ----- Инициализация логгера (куда писать логи) -----
    QString appPath = QFileInfo(QCoreApplication::applicationFilePath()).absolutePath();
    Logger::initialize(appPath);

    // ----- Инициализация криптоменеджера -----
    CryptoManager* crypto = CryptoManager::getInstance();

    if (!crypto->initialize(QString::fromStdString(password))) {
        std::cout << "[ОШИБКА] Ошибка инициализации крипто-менеджера" << std::endl;
        Logger* logger = Logger::getInstance();
        if (logger) {
            logger->logError("Ошибка инициализации крипто-менеджера");
        }

        secureStringClear(password);
        CryptoManager::destroyInstance();
        Logger::destroyInstance();
        return 1;
    }

    // Пароль больше не нужен — затираем
    secureStringClear(password);

    // ----- Запуск обработки -----
    bool success = crypto->processFolder(QString::fromStdString(folderPathInput), mode);

    // ----- Очистка перед выходом -----
    CryptoManager::destroyInstance();
    Logger::destroyInstance();

    return success ? 0 : 1;
}
