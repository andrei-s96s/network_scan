# Настройка GitHub Actions для автоматической сборки Docker

## Обзор

Этот документ описывает настройку автоматической сборки и публикации Docker образа в Docker Hub при каждом push в GitHub.

## Требования

1. **GitHub репозиторий** с кодом проекта
2. **Docker Hub аккаунт** с репозиторием `andreis1s/net_scan`
3. **GitHub Secrets** для хранения учетных данных Docker Hub

## Настройка GitHub Secrets

### 1. Создание Personal Access Token в Docker Hub

1. Войдите в [Docker Hub](https://hub.docker.com)
2. Перейдите в **Account Settings** → **Security**
3. Нажмите **New Access Token**
4. Введите название токена (например: `github-actions`)
5. Выберите **Read & Write** права
6. Скопируйте созданный токен

### 2. Добавление Secrets в GitHub

1. Перейдите в ваш GitHub репозиторий
2. Нажмите **Settings** → **Secrets and variables** → **Actions**
3. Нажмите **New repository secret**
4. Добавьте следующие secrets:

| Name | Value |
|------|-------|
| `DOCKER_USERNAME` | Ваш Docker Hub username |
| `DOCKER_PASSWORD` | Personal Access Token из Docker Hub |

## Workflow файл

Файл `.github/workflows/docker-build.yml` уже создан и настроен для:

- **Триггеры**: push в main/develop, теги v*, pull requests
- **Платформы**: linux/amd64, linux/arm64
- **Кэширование**: GitHub Actions cache для ускорения сборки
- **Автоматическая публикация**: только для push (не для PR)

## Тегирование

### Автоматические теги

Workflow автоматически создает теги:

- **Ветки**: `main`, `develop` → `andreis1s/net_scan:main`, `andreis1s/net_scan:develop`
- **Теги**: `v2.0.0` → `andreis1s/net_scan:2.0.0`, `andreis1s/net_scan:2.0`
- **SHA**: `andreis1s/net_scan:main-abc1234`

### Создание релиза

```bash
# Создать тег
git tag v2.0.0

# Push тег
git push origin v2.0.0
```

## Мониторинг

### GitHub Actions

1. Перейдите в **Actions** вкладку репозитория
2. Выберите **Docker Build and Push** workflow
3. Просматривайте логи выполнения

### Docker Hub

1. Проверьте [andreis1s/net_scan](https://hub.docker.com/r/andreis1s/net_scan)
2. Убедитесь, что образ обновился
3. Проверьте теги и платформы

## Troubleshooting

### Ошибки аутентификации

```
Error: unauthorized: authentication required
```

**Решение**: Проверьте правильность `DOCKER_USERNAME` и `DOCKER_PASSWORD` в GitHub Secrets.

### Ошибки сборки

```
Error: failed to solve: process "/bin/sh -c ..." did not complete successfully
```

**Решение**: 
1. Проверьте Dockerfile на локальной машине
2. Убедитесь, что все зависимости указаны корректно
3. Проверьте логи сборки в GitHub Actions

### Проблемы с кэшем

```
Error: failed to compute cache key
```

**Решение**: 
1. Очистите кэш в GitHub Actions
2. Перезапустите workflow

## Оптимизация

### Ускорение сборки

1. **Многоэтапная сборка**: Используйте `--target` для промежуточных образов
2. **Кэширование слоев**: Оптимизируйте порядок команд в Dockerfile
3. **Параллельная сборка**: Используйте `buildx` для мультиплатформенной сборки

### Уменьшение размера образа

1. **Alpine Linux**: Используйте `python:3.11-alpine` как базовый образ
2. **Многоэтапная сборка**: Отделите build и runtime этапы
3. **Очистка кэша**: Удаляйте временные файлы после установки

## Безопасность

### Best Practices

1. **Secrets**: Никогда не коммитьте учетные данные в код
2. **Минимальные права**: Используйте токены с минимальными правами
3. **Сканирование**: Регулярно сканируйте образы на уязвимости
4. **Обновления**: Своевременно обновляйте базовые образы

### Сканирование уязвимостей

Добавьте в workflow:

```yaml
- name: Scan image
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.meta.outputs.version }}
    format: 'sarif'
    output: 'trivy-results.sarif'
```

## Дополнительные возможности

### Уведомления

Добавьте уведомления в Slack/Telegram при успешной сборке:

```yaml
- name: Notify success
  if: success()
  uses: 8398a7/action-slack@v3
  with:
    status: success
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### Автоматическое тестирование

Добавьте тесты перед публикацией:

```yaml
- name: Test image
  run: |
    docker run --rm andreis1s/net_scan:latest python -m pytest tests/
```

## Заключение

После настройки GitHub Actions:

1. Каждый push в main/develop автоматически собирает и публикует образ
2. Теги создают версионированные образы
3. Pull requests проверяются без публикации
4. Мультиплатформенная поддержка (amd64, arm64)

Это обеспечивает непрерывную интеграцию и доставку (CI/CD) для Docker образа.
