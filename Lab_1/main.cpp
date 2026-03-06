#include <QCoreApplication>
#include <QFileInfo>
#include <windows.h>
#include <iostream>

#include "CryptoManager.h"
#include "FileUtils.h"
#include "FileInfo.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    QString currentPath =
        QFileInfo(QCoreApplication::applicationFilePath()).absolutePath();

    std::cout << "Текущая директория: "
              << currentPath.toStdString() << std::endl << std::endl;

    std::string folderName;
    std::cout << "Введите название папки для поиска: ";
    std::getline(std::cin, folderName);

    std::string password;
    std::cout << "Введите пароль: ";
    std::getline(std::cin, password);

    std::string mode;
    std::cout << "Выберите режим (1 - шифрование, 2 - дешифрование): ";
    std::getline(std::cin, mode);

    QString folderPath =
        findFolder(QString::fromStdString(folderName), currentPath);

    if (folderPath.isEmpty()) {
        std::cout << "Папка не найдена." << std::endl;
        return 0;
    }

    CryptoManager* crypto = CryptoManager::getInstance();
    if (!crypto->initialize(QString::fromStdString(password))) {
        std::cout << "Ошибка инициализации." << std::endl;
        CryptoManager::destroyInstance();
        return 0;
    }

    password.assign(password.size(), '0');

    QList<FileInfo> files;
    collectFilesInfo(folderPath, folderPath, files);

    if (mode == "1") {
        calculateAndPrintHashes(files, "ДО ШИФРОВАНИЯ");

        for (auto &file : files) {
            QString outputPath;
            crypto->encryptFile(file.path, outputPath);
        }
    }
    else if (mode == "2") {
        for (auto &file : files) {
            QString outputPath;
            crypto->decryptFile(file.path, outputPath);
        }

        calculateAndPrintHashes(files, "ПОСЛЕ ДЕШИФРОВАНИЯ");
    }

    CryptoManager::destroyInstance();
    return 0;
}
