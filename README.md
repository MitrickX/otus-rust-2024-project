# OTUS Rust Basic (2024) project

## Тех задание
Микросвервис авторизации

Основа базируется [на этом ТЗ сервиса антибрутфорса](https://github.com/OtusGolang/final_project/blob/master/01-anti-bruteforce.md)

Моя реализация на [Golang](https://github.com/MitrickX/otus-golang-2019-project-antibruteforce)


Помимо логики антибрутфорса реализовано
1) Хранение авторизационных данных (логин, хеш пароля, набор разрешений)
2) Генерация при верных авторизацонных данных авторизацонного токена на основе JWT (без ограниченния по TTL, это не сделано)
3) Проверка валидности авторизацонного токена
4) Все методы сервиса (кроме метода для авторизации) проверяют необходимое разрешение

**Как запускать**
1) Запустить все тесты - юнит, интеграционные, BDD gherkin api тесты - в отдельном контейнере

```
 make tests
```

2) Запустить сервис 

```
make restart
```

3) Запустить UI grpc клиент

```
grpcui -plaintext '[::1]:50051'
```

Для вызова методов понадобится токен зарегестрированной роли. Для получения токена нужно вызвать auth для тестовой бот-учетки, которую можно подглядеть в deploy/docker-compose-tests.yaml


Беклог
* Доделать Refresh API
* В релизере передавать &Role
* Структурное логивароние, попробовать - https://github.com/slog-rs/slog 
* Подключить ELK - https://github.com/elkninja/elastic-stack-docker-part-one/tree/main
* Подключить Kafka для рассылки событий системы
* REST-API шлюз 
* thiserror