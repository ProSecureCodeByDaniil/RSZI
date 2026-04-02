/*
#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

class Calculator {
private:
    std::string name;

public:
    Calculator(const std::string& n) : name(n) {
        std::cout << "Создан калькулятор: " << name << std::endl;
    }

    ~Calculator() {
        std::cout << "Удалён калькулятор: " << name << std::endl;
    }

    int add(int a, int b) {
        return a + b;
    }
};

int main() {

    // Для русского языка в выводе в консоли
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Можно создать несколько экземпляров
    Calculator calc1("Калькулятор 1");
    Calculator calc2("Калькулятор 2");

    std::cout << "2 + 3 = " << calc1.add(2, 3) << std::endl;
    std::cout << "5 + 7 = " << calc2.add(5, 7) << std::endl;

    // calc1 и calc2 удаляются автоматически при выходе из main
    return 0;
}
*/
