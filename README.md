# CreateADUser
Скрипт для быстрого создания пользователя Active Directory
Минимальна ядлина пароля берется из AD, количество спецсимволов в составе пароля можно изменить, выпольнив поиск в скрипте по слову "#$cmplx" и изменить цифру слева.
При выборе групп пробелы ставить не нужно, есть разница между регистром символов. Проверки на некорректный ввод нет.
Данные созданного пользователя и пароль сохраняются в корене каталога, из которого запущен скрипт. Путь сохранения можно прописать вручную вместо переменной "$PSScriptRoot". Если файл с пользователями не получается открыть на запись создается еще один. При будущих запусках скрипт пытается открыть файлы на запись начиная с первого.

Скрипт предоставляется "как есть".
