# Task Manager Backend

Простой backend-сервер для управления задачами, реализованный на **Spring Boot** с использованием **JWT-аутентификации**.

Функционал

- Регистрация и вход с использованием JWT
- CRUD-операции для задач
- Защищённые эндпоинты
- Шифрование паролей (BCrypt)
- REST API, совместимый с Postman

Технологии

- Java 17
- Spring Boot
- Spring Security
- JWT (JSON Web Token)
- PostgreSQL
- Maven


🧪 Тестирование через Postman
POST /api/auth/register — регистрация

POST /api/auth/login — вход и получение токена

GET /api/tasks — получить список задач (нужен JWT)

POST /api/tasks — создать задачу

PUT /api/tasks/{id} — обновить задачу

DELETE /api/tasks/{id} — удалить задачу
