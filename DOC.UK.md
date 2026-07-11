# auth - довідник

`auth` - набір примітивів автентифікації. Повний український довідник;
англійською - [DOC.md](DOC.md).

## Зміст

- [Subject і контекст](#subject-і-контекст)
- [Паролі](#паролі)
- [Access-токени](#access-токени)
- [Middleware](#middleware)
- [Refresh-токени](#refresh-токени)
- [Залежності](#залежності)
- [Межі](#межі)

## Subject і контекст

```go
type Subject struct {
	ID     string
	Email  string
	Roles  []string
	Scopes []string
}
```

`WithSubject(ctx, s)` кладе subject; `SubjectFrom(ctx)` дістає. `HasRole`/
`HasScope` - зручні перевірки. Middleware наповнює subject; хендлери читають.

## Паролі

```go
type PasswordHasher interface {
	Hash(password []byte) (encoded string, err error)
	Verify(encoded string, password []byte) error
}
```

`NewPBKDF2(opts...)` повертає PBKDF2-HMAC-SHA256 hasher (stdlib `crypto/pbkdf2`).
Дефолти: 600000 ітерацій, 32-байтовий ключ, 16-байтова випадкова сіль.
`WithIterations(n)` регулює вартість. Закодована форма -
`pbkdf2-sha256$iterations$salt$digest` (base64), а `Verify` порівнює у constant
time.

Щоб використати Argon2id, реалізуйте `PasswordHasher` у застосунку (прийнявши
залежність `golang.org/x/crypto` там); `auth` лишається без залежностей.

## Access-токени

```go
tm := auth.NewTokenManager(secret, opts...)
token, err := tm.Issue(subject)
sub, err := tm.Verify(token)
```

| Опція | Ефект | Дефолт |
|-------|-------|--------|
| `WithIssuer(s)` | задати й вимагати iss | "" |
| `WithAudience(s)` | задати й вимагати aud | "" |
| `WithTTL(d)` | час життя access-токена | 15m |
| `WithLeeway(d)` | допуск на розбіжність годинника | 0 |
| `WithClock(fn)` | джерело часу (тести) | time.Now |

`Issue` кодує ID subject-а як `sub`, а email/roles/scopes - як кастомні claim-и.
`Verify` (через `goloop/jwt`) вимагає HS256, наявний `exp`, issuer і audience, і
відновлює subject.

## Middleware

```go
func (m *TokenManager) Bearer(next http.Handler) http.Handler
func (m *TokenManager) Cookie(name string, next http.Handler) http.Handler
func Require(next http.Handler) http.Handler
func RequireScope(scope string, next http.Handler) http.Handler
```

`Bearer` читає `Authorization: Bearer <token>`; `Cookie` читає названу cookie.
Обидва: валідний токен ставить subject; присутній, але невалідний токен дає 401;
відсутній токен пропускає далі, лишаючи enforcement на `Require`/`RequireScope`.
`Require` дає 401 без subject; `RequireScope` дає 401 без subject або 403 без
scope.

## Refresh-токени

```go
rt, token, err := auth.NewRefreshToken(subject, ttl)
id, secret, err := auth.ParseRefreshToken(token)
err = rt.Verify(secret) // constant-time; перевіряє строк дії
```

`NewRefreshToken` повертає запис для зберігання (що тримає лише SHA-256 хеш
секрету) і непрозорий токен `id.secret` для клієнта. Перевірка шукає запис за
`id`, тоді перевіряє секрет у constant time. Секрет - випадковий, високої
ентропії, тож простого хешу достатньо (на відміну від пароля).

```go
type RefreshStore interface {
	Save(ctx, RefreshToken) error
	Rotate(ctx, oldID string, next RefreshToken) error
	Revoke(ctx, id string) error
}
```

`Rotate` атомарно відкликає старий токен і зберігає новий. Реалізуйте store над
вашою БД.

## Залежності

`auth` залежить лише від стандартної бібліотеки та `github.com/goloop/jwt`
(сусідній модуль) для підпису HS256-токенів. Сторонніх залежностей немає.

## Межі

`auth` не містить: user-репозиторію, RBAC-схеми, OAuth/OIDC, UI, надсилання
email чи міграцій. Він дає крипто, токени й middleware; ви володієте таблицями
користувачів і refresh-токенів.
