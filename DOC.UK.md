# auth - довідник

`auth` - набір примітивів автентифікації. Повний український довідник;
англійською - [DOC.md](DOC.md).

## Зміст

- [Subject і контекст](#subject-і-контекст)
- [Паролі](#паролі)
- [Access-токени](#access-токени)
- [Middleware](#middleware)
- [Refresh-токени](#refresh-токени)
- [Як писати спільний стор](#як-писати-спільний-стор)
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
time. `Verify` також перевіряє межі параметрів, тож зіпсований чи ворожий хеш
(однобайтовий digest, мільярд ітерацій) відхиляється до будь-якого виведення
ключа, а не послаблює перевірку і не палить CPU.

Hasher також реалізує `Rehasher`:

```go
type Rehasher interface {
	NeedsRehash(encoded string) bool
}
```

Викликайте `NeedsRehash` після успішного `Verify`, щоб оновити збережений хеш,
коли дефолти посилюються:

```go
if err := h.Verify(stored, pw); err == nil {
	if rh, ok := h.(auth.Rehasher); ok && rh.NeedsRehash(stored) {
		newHash, _ := h.Hash(pw) // зберегти newHash
	}
}
```

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

Секрет має бути не коротшим за 32 байти (мінімум HS256); він копіюється при
створенні, тож викликач може перевикористати чи занулити свій зріз. `Issue`
кодує ID subject-а як `sub`, а email/roles/scopes - як кастомні claim-и.
`Verify` (через `goloop/jwt`) вимагає HS256, наявний `exp`, issuer і audience, і
відновлює subject.

## Middleware

```go
func (m *TokenManager) Bearer(next http.Handler) http.Handler
func (m *TokenManager) Cookie(name string, next http.Handler) http.Handler
func (m *TokenManager) Protect(next http.Handler) http.Handler
func (m *TokenManager) ProtectScope(scope string, next http.Handler) http.Handler
func Require(next http.Handler) http.Handler
func RequireScope(scope string, next http.Handler) http.Handler
```

`Bearer` читає `Authorization: Bearer <token>`; `Cookie` читає названу cookie.
Обидва: валідний токен ставить subject; присутній, але невалідний токен дає 401;
відсутній токен пропускає далі, лишаючи enforcement на `Require`/`RequireScope`.
`Require` дає 401 без subject; `RequireScope` дає 401 без subject або 403 без
scope.

`Protect` - це `Bearer` + `Require` одним викликом, а `ProtectScope` - `Bearer` +
`RequireScope`. Для маршруту, який ніколи не має бути доступним без автентифікації,
надавайте перевагу саме їм: обгортка лише `Bearer` пропускає анонімний запит
далі, і це легка помилка.

## Refresh-токени

```go
rt, token, err := auth.NewRefreshToken(subject, ttl)
id, secret, err := auth.ParseRefreshToken(token)
err = rt.Verify(secret) // constant-time; перевіряє строк дії
```

`NewRefreshToken` повертає запис для зберігання (що тримає лише SHA-256 хеш
секрету) і непрозорий токен `id.secret` для клієнта. Subject має бути непорожнім
(`ErrEmptySubject`), а ttl - додатним (`ErrInvalidTTL`), тож токен ніколи не
створюється без власника чи вже простроченим. Перевірка шукає запис за `id`,
тоді перевіряє секрет у constant time. Секрет - випадковий, високої ентропії,
тож простого хешу достатньо (на відміну від пароля). `Verify` повертає
розбіжність секрету раніше за строк дії; злийте обидві в одну непрозору помилку,
якщо показуєте їх, щоб простроченим токеном не можна було перевірити вгаданий
секрет.

```go
type RefreshStore interface {
	Save(ctx, RefreshToken) error
	Rotate(ctx, oldID string, next RefreshToken) error
	Revoke(ctx, id string) error
}
```

`Rotate` атомарно відкликає старий токен і зберігає новий. Реалізуйте store над
вашою БД.

## Як писати спільний стор

`MemoryRefreshStore` - для тестів і однопроцесних програм. Сервісу з кількома
інстансами потрібен стор, який вони бачать спільно, а це код застосунку: `auth`
не бере залежності ні від бази, ні від кешу.

Чого саме вимагає контракт, з самого інтерфейсу не видно, тож нижче він увесь -
разом із помилками, які роблять раз за разом.

**Ротація має бути однією атомарною дією.** Читання, звірка й підміна не можуть
бути окремими зверненнями: два клієнти, що подали той самий токен одночасно,
мусять дати рівно одного наступника. У Redis це означає скрипт, а не
послідовність команд:

```lua
-- KEYS[1] токен, який ротуємо, KEYS[2] наступник,
-- KEYS[3] індекс суб'єкта.
-- ARGV[1] запис наступника, ARGV[2] старий id, ARGV[3] новий id, ARGV[4] ttl.
if redis.call('del', KEYS[1]) == 1 then
  redis.call('set', KEYS[2], ARGV[1], 'EX', ARGV[4])
  redis.call('srem', KEYS[3], ARGV[2])
  redis.call('sadd', KEYS[3], ARGV[3])
  redis.call('expire', KEYS[3], ARGV[4])
  return 1
end
return 0
```

`del`, що повернув 1, - це водночас і перевірка, і заявка: хто видалив ключ, той
і виконав єдину ротацію, решта отримує 0 і `ErrRefreshUsed`. Дві команди -
спершу `get`, потім `del` - лишають вікно, у якому перевірку проходять обидва.

**Індекс суб'єкта оновлюється в трьох місцях.** `Save`, `Rotate` і `Revoke` -
усі три змінюють набір токенів суб'єкта. Оновіть у двох із трьох, і `RevokeAll`
відзвітує про успіх, поки сесія працює далі: найгірший можливий результат для
кнопки «вийти всюди». Дайте індексу час життя не менший за найдовший токен у
ньому, інакше він протухне першим і токени переживуть власний індекс.

**Стор, до якого не достукались, нічого не вирішив.** Повертайте помилку
інфраструктури як є. `ErrRefreshUsed` - це твердження про токен, і викликач, що
сприйме його буквально, завершить усі сесії суб'єкта через мережевий збій.

**Epoch замість індексу** - розумна альтернатива: один час на суб'єкта, і токен
мертвий, якщо виданий раніше. Вона позбавляє від індексу в трьох місцях і має
одну пастку. Звірка epoch мусить бути *всередині* тієї самої атомарної операції,
що й підміна. Звірена окремо, вона пропускає відкликаний токен, той підміняє
себе наступником із міткою після epoch, і вся родина повертається. Тримайте
epoch із наносекундною точністю: при секундній роздільності токен, виданий за
200 мс до скидання пароля, порівнюється як новіший і виживає, - а це саме той
токен, що був у руках зловмисника.

**А тоді доведіть це.** `auth/authtest` проганяє контракт проти реалізації,
включно з паралельністю:

```go
func TestRedisStore(t *testing.T) {
    authtest.RefreshStore(t, func(t *testing.T) auth.RefreshStore {
        s := newRedisStore(t, redisURL)
        t.Cleanup(func() { s.flush() })
        return s
    })
}
```

Він перевіряє ті необов'язкові інтерфейси, які стор реалізує, і пропускає решту.
Кожна з помилок вище має свою перевірку, зокрема ті, що проходять один
послідовний прогін: стор із неатомарною ротацією падає на перевірці
паралельності, а стор, чий індекс не оновлюється в `Rotate`, - на `RevokeAll`.

## Залежності

`auth` залежить лише від стандартної бібліотеки та `github.com/goloop/jwt`
(сусідній модуль) для підпису HS256-токенів. Сторонніх залежностей немає.

## Межі

`auth` не містить: user-репозиторію, RBAC-схеми, OAuth/OIDC, UI, надсилання
email чи міграцій. Він дає крипто, токени й middleware; ви володієте таблицями
користувачів і refresh-токенів.
