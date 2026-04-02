/*
#include <iostream>
#include <QCoreApplication>
#include <QFile>
#include <QDateTime>
#include <QDir>

#ifdef _WIN32
#include <windows.h>
#endif

class SimpleLogger {
private:
    QFile logFile;

public:
    SimpleLogger(const QString& filename) {
        logFile.setFileName(filename);
        if (logFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
            write("Логгер инициализирован");
        }
    }

    ~SimpleLogger() {
        if (logFile.isOpen()) {
            write("Логгер закрыт");
            logFile.close();
        }
    }

    void write(const QString& message) {
        if (!logFile.isOpen()) return;

        // Форматируем сообщение с датой и временем
        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
        QString formatted = timestamp + " - " + message + "\n";

        // Записываем в файл
        logFile.write(formatted.toUtf8());
        logFile.flush();

        // Для проверки можно ещё включить вывод в консоль
        //std::cout << formatted.toStdString();
    }
};

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Путь к папке с программой
    QString appPath = QCoreApplication::applicationDirPath();
    QString logPath = appPath + "/my_log.txt";

    std::cout << "Лог-файл будет создан по пути: " << logPath.toStdString() << std::endl;

    SimpleLogger logger(logPath);

    logger.write("Программа запущена");
    logger.write("Выполняется операция...");
    logger.write("Операция завершена успешно");

    std::cout << "\nНажмите Enter для выхода..." << std::endl;
    std::cin.get();

    return 0;
}
*/
