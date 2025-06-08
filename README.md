# 📝 Task Manager Backend

Backend-сервис на Spring Boot для управления задачами с JWT-аутентификацией.

## 🔍 Возможности

- ✅ Регистрация и аутентификация пользователей (JWT)
- 📋 Создание, редактирование, удаление и просмотр задач
- 🔒 Защита маршрутов и токен-авторизация
- 🧩 REST API, готовый для работы с Postman

## 🛠️ Стек технологий

- Java 17
- Spring Boot 3
- Spring Security
- JWT (jjwt)
- PostgreSQL
- Maven
- Lombok

## ⚙️ Установка

1. Клонируйте репозиторий:

```bash
git clone https://github.com/AdamAmirkulov/taskmanager-backend.git
cd taskmanager-backend
```

2. Настройте `application.properties`:

```properties
# База данных
spring.datasource.url=jdbc:postgresql://localhost:5432/taskmanager
spring.datasource.username=your_db_user
spring.datasource.password=your_db_password

# JWT
jwt.secret=your_super_secret_key_which_is_at_least_256_bits_long
jwt.expiration=86400000
```

3. Запустите проект:

```bash
./mvnw spring-boot:run
```

## 📬 Примеры API-запросов (Postman)

### 🔐 Аутентификация

**POST /api/auth/register**  
Регистрация нового пользователя  
```json
{
  "username": "john",
  "password": "password123"
}
```

**POST /api/auth/login**  
Вход в систему  
```json
{
  "username": "john",
  "password": "password123"
}
```

Ответ:
```json
{
  "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Не забудьте передавать токен в заголовке:

```
Authorization: Bearer <ваш токен>
```

### 📋 Работа с задачами

**GET /api/tasks** — Получить список задач  
**POST /api/tasks** — Создать задачу  
**PUT /api/tasks/{id}** — Обновить задачу  
**DELETE /api/tasks/{id}** — Удалить задачу

## 📂 Структура проекта

```
src/
├── main/
│   ├── java/com/example/taskmanager/
│   │   ├── config/           # Настройки безопасности
│   │   ├── controller/       # Контроллеры
│   │   ├── filter/           # JWT-фильтр
│   │   ├── model/            # Сущности
│   │   ├── repository/       # Репозитории
│   │   └── service/          # Бизнес-логика
│   └── resources/
│       └── application.properties
```

## 👤 Автор

- GitHub: [Adam Amirkulov](https://github.com/AdamAmirkulov)
