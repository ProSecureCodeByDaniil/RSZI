/*
#include <iostream>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QString>

#ifdef _WIN32
#include <windows.h>
#endif
*/
// Документирующий комментарии в стиле Doxygen (если нужна будет автоматическая генерация документации программы)
// @param и другие это стандартизированная структура тегов
/**
 * Рекурсивный обход всех файлов в директории
 * @param path - путь к папке для обхода
 * @param depth - текущая глубина (для отступов)
 */
/*
void listFilesRecursively(const QString& path, int depth = 0) {
    QDir dir(path);

    // Проверяем, существует ли папка
    if (!dir.exists()) {
        std::cout << "Папка не существует!" << std::endl;
        return;
    }

    // Получаем список всех элементов (папки и файлы, исключая . и ..)
    QFileInfoList entries = dir.entryInfoList(QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot);

    // Отступ для наглядной структуры
    std::string indent(depth * 2, ' ');

    for (const QFileInfo& entry : entries) {
        if (entry.isDir()) {
            // Это папка - выводим и рекурсивно заходим внутрь
            std::cout << indent << "[ПАПКА]" << entry.fileName().toStdString() << "/" << std::endl;
            listFilesRecursively(entry.absoluteFilePath(), depth + 1);
        }
        else if (entry.isFile()) {
            // Это файл - выводим информацию
            std::cout << indent << "[ФАЙЛ]" << entry.fileName().toStdString()
                      << " (" << entry.size() << " байт)" << std::endl;
        }
    }
}

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Запрашиваем путь у пользователя
    std::string inputPath;
    std::cout << "Введите путь к папке: ";
    std::getline(std::cin, inputPath);

    QString path = QString::fromStdString(inputPath);

    std::cout << "\nСодержимое папки:" << std::endl;
    std::cout << "=================" << std::endl;
    listFilesRecursively(path);

    return 0;
}
*/
