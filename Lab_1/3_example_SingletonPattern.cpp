#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

class CryptoManager {
private:
    static CryptoManager* instance;  // Единственный экземпляр
    std::string key;

    // Приватный конструктор - нельзя создать снаружи
    CryptoManager() {
        std::cout << "Создан CryptoManager (один раз)" << std::endl;
    }

    ~CryptoManager() {
        std::cout << "Удалён CryptoManager" << std::endl;
    }

public:
    // Запрет копирования
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    static CryptoManager* getInstance() {
        if (!instance) {
            instance = new CryptoManager();
        }
        return instance;
    }

    static void destroyInstance() {
        delete instance;
        instance = nullptr;
    }

    void setKey(const std::string& k) {
        key = k;
        std::cout << "Ключ установлен: " << key << std::endl;
    }

    void encrypt() {
        std::cout << "Шифрование с ключом: " << key << std::endl;
    }
};

// Инициализация статического члена
CryptoManager* CryptoManager::instance = nullptr;

int main() {

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Нельзя создать: CryptoManager cm; // Ошибка!

    // Получаем единственный экземпляр
    CryptoManager* cm1 = CryptoManager::getInstance();
    cm1->setKey("secret123");

    // cm2 указывает на тот же объект!
    CryptoManager* cm2 = CryptoManager::getInstance();
    cm2->encrypt();  // Использует тот же ключ

    // Очистка
    CryptoManager::destroyInstance();

    return 0;
}
