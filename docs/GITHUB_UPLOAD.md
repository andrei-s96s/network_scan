# Загрузка проекта на GitHub

## Пошаговая инструкция

### 1. Создание репозитория на GitHub

1. Перейдите на [GitHub](https://github.com)
2. Нажмите **New repository** (зеленая кнопка)
3. Заполните форму:
   - **Repository name**: `network-scanner`
   - **Description**: `Network Scanner with Web Interface and Docker Support`
   - **Visibility**: Public (или Private по желанию)
   - **Initialize with**: НЕ ставьте галочки (у нас уже есть код)
4. Нажмите **Create repository**

### 2. Настройка Git конфигурации

```bash
# Настройка пользователя (если еще не настроено)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Проверка настроек
git config --global --list
```

### 3. Подключение к GitHub репозиторию

```bash
# Добавить remote origin
git remote add origin https://github.com/andreis1s/network-scanner.git

# Проверить remote
git remote -v
```

### 4. Загрузка кода

```bash
# Push основную ветку
git push -u origin main

# Push тег
git push origin v2.0.0
```

### 5. Настройка GitHub Actions

1. Перейдите в **Settings** → **Secrets and variables** → **Actions**
2. Нажмите **New repository secret**
3. Добавьте secrets:
   - `DOCKER_USERNAME`: ваш Docker Hub username
   - `DOCKER_PASSWORD`: Personal Access Token из Docker Hub

### 6. Создание Personal Access Token в Docker Hub

1. Войдите в [Docker Hub](https://hub.docker.com)
2. Перейдите в **Account Settings** → **Security**
3. Нажмите **New Access Token**
4. Название: `github-actions`
5. Права: **Read & Write**
6. Скопируйте токен и добавьте в GitHub Secrets

### 7. Проверка автоматической сборки

1. Перейдите в **Actions** вкладку на GitHub
2. Должен запуститься workflow **Docker Build and Push**
3. Дождитесь завершения (обычно 5-10 минут)
4. Проверьте [Docker Hub](https://hub.docker.com/r/andreis1s/net_scan)

## Команды для выполнения

```bash
# 1. Настройка Git (если нужно)
git config --global user.name "Andrei Sych"
git config --global user.email "andrei.sych69@gmail.com"

# 2. Подключение к GitHub
git remote add origin https://github.com/andreis1s/network-scanner.git

# 3. Загрузка кода
git push -u origin main
git push origin v2.0.0

# 4. Проверка статуса
git status
git remote -v
git tag -l
```

## Проверка результата

### GitHub
- ✅ Репозиторий создан
- ✅ Код загружен
- ✅ Тег v2.0.0 создан
- ✅ GitHub Actions настроены

### Docker Hub
- ✅ Образ автоматически собран
- ✅ Теги созданы: `latest`, `2.0.0`, `2.0`
- ✅ Мультиплатформенная поддержка (amd64, arm64)

### Документация
- ✅ README.md с описанием
- ✅ CHANGELOG.md с историей изменений
- ✅ DOCKER.md с инструкциями
- ✅ Лицензия MIT

## Следующие шаги

1. **Добавить описание в GitHub**: Редактировать README в веб-интерфейсе
2. **Настроить Issues**: Включить шаблоны для bug reports и feature requests
3. **Добавить Wiki**: Дополнительная документация
4. **Настроить ветки**: develop для разработки, main для релизов

## Troubleshooting

### Ошибка аутентификации
```bash
# Настройка токена GitHub
git remote set-url origin https://YOUR_TOKEN@github.com/andreis1s/network-scanner.git
```

### Ошибка push
```bash
# Принудительный push (осторожно!)
git push -f origin main
```

### Проблемы с GitHub Actions
1. Проверьте Secrets в Settings
2. Проверьте права репозитория
3. Проверьте логи в Actions вкладке

## Результат

После выполнения всех шагов у вас будет:

- 🚀 **GitHub репозиторий** с полным кодом проекта
- 🐳 **Docker Hub образ** с автоматической сборкой
- 📚 **Документация** для пользователей и разработчиков
- 🔄 **CI/CD pipeline** для автоматических релизов
- 🏷️ **Версионирование** с тегами v2.0.0

Проект готов для использования сообществом! 🎉
