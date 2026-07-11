[![Go Reference](https://img.shields.io/badge/godoc-reference-blue)](https://pkg.go.dev/github.com/goloop/auth) [![License](https://img.shields.io/badge/license-MIT-brightgreen)](https://github.com/goloop/auth/blob/master/LICENSE) [![Stay with Ukraine](https://img.shields.io/static/v1?label=Stay%20with&message=Ukraine%20♥&color=ffD700&labelColor=0057B8&style=flat)](https://u24.gov.ua/)

# auth

`auth` дає примітиви автентифікації - хешування паролів, access-токени,
HTTP-middleware і ротацію refresh-токенів - не стаючи identity-платформою. Без
user-репозиторію, без RBAC-схеми, без OAuth. Persistence і керування
користувачами лишаються у вашому застосунку.

Лише стандартна бібліотека, плюс [`goloop/jwt`](https://github.com/goloop/jwt)
для підпису токенів.

## Встановлення

```bash
go get github.com/goloop/auth
```

## Паролі

```go
hasher := auth.NewPBKDF2() // PBKDF2-HMAC-SHA256, лише stdlib

encoded, err := hasher.Hash([]byte(password)) // зберігаємо encoded
err = hasher.Verify(encoded, []byte(attempt)) // nil при збігу
```

Закодований рядок самоописовий (`pbkdf2-sha256$iter$salt$digest`).
`PasswordHasher` - інтерфейс, тож можна підключити Argon2id без зміни викликів.

## Access-токени

```go
tm := auth.NewTokenManager(secret,
	auth.WithIssuer("api"),
	auth.WithTTL(15*time.Minute),
)

token, err := tm.Issue(auth.Subject{ID: "user-1", Scopes: []string{"read"}})
sub, err := tm.Verify(token)
```

Токени - HS256 JWT: обов'язковий строк дії, constant-time перевірка, суворий
алгоритм.

## Middleware

```go
h := tm.Bearer(auth.Require(handler))                    // 401 без валідного токена
h = tm.Cookie("session", auth.RequireScope("admin", handler))

sub, ok := auth.SubjectFrom(r.Context())
```

`Bearer`/`Cookie` автентифікують, коли токен присутній (401 якщо невалідний,
пропуск якщо відсутній); `Require` і `RequireScope` вимагають наявності й scope.

## Refresh-токени

```go
rt, token, err := auth.NewRefreshToken(userID, 30*24*time.Hour)
// зберігаємо rt (лише його hash), token віддаємо клієнту

id, secret, err := auth.ParseRefreshToken(token)
// шукаємо rt за id, тоді:
err = rt.Verify(secret)
```

`RefreshStore` - контракт persistence (`Save`/`Rotate`/`Revoke`); реалізуйте
його над вашою БД.

## Межі

`auth` не містить user-репозиторію, RBAC-схеми, OAuth/OIDC, надсилання email чи
міграцій. Він дає крипто й middleware; ви лишаєте контроль над таблицями
користувачів і токенів.

## Документація

- Англійський довідник: [DOC.md](DOC.md)
- Український довідник: [DOC.UK.md](DOC.UK.md)

## Ліцензія

MIT - див. [LICENSE](LICENSE).
