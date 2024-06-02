# OTUS Rust Basic (2024) project

## Тех задание
Программа минимум микросервис антибрутфорс для авторизации - полное ТЗ тут https://github.com/OtusGolang/final_project/blob/master/01-anti-bruteforce.md

Моя реализация на ГО тут https://github.com/MitrickX/otus-golang-2019-project-antibruteforce 

По факту просто перенести это и есть программа минимум

Плюс, если время останется, доделать его до полного сервиса авторизатора
1) Хранение авторизационных данных (логин, хеш пароля, набор разрешений)
2) Генерация при верных авторизацонных данных авторизацонного токена на основе JWT (с ограниченным TTL)
3) Проверка валидности авторизацонного токена
4) Админ-АПИ (нужны разрешения в БД), для управления. Авторизация тоже на основе этого же сервиса

**Подготовить окружение**
1) Поставить postgresql
2) Создать роль и БД

```
psql -U postgres

create role otus with createdb login password '1234';
create database auth with owner 'otus';
create database auth_test with owner 'otus';
\q
```


3) Запустить интеграционные тесты
```
cargo test --package server --test test_ip_list -- --nocapture
```


**Examples**

```
grpcurl -plaintext -d '{"login": "test", "password": "1234", "ip": "127.0.0.1"}' '[::1]:50051' auth.Auth.Auth
```

```
grpcui -plaintext '[::1]:50051'
```