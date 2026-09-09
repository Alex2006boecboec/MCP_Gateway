# Security Hardening Plan v2 — MCP Shield Cloud (Postgres + Security)

**Цель:** перевести cloud-дашборд на PostgreSQL (Railway) и закрыть все
уязвимости до публичного релиза.

**Принцип:** fail-closed везде. SQLite остаётся только для тестов/локала.
Production = Postgres.

---

## Этап 0 — Миграция SQLite → PostgreSQL (фундамент, делается первым)

### 0.1 Абстракция DB слоя (Storage protocol)

**Зачем:** один код, два backend (SQLite для тестов, Postgres для prod),
переключение через env.

**Что сделать:**
- Создать `mcp_shield/cloud/storage.py` с `Storage` Protocol (abstract):
  - `create_org(name) -> Org`
  - `get_org(org_id) -> Org | None`
  - `create_user(org_id, email, password_hash, role) -> User`
  - `get_user_by_email(email) -> User | None`
  - `get_user(user_id) -> User | None`
  - `list_users(org_id) -> list[User]`
  - `update_password(user_id, new_hash) -> bool`
  - `delete_user(user_id) -> bool`
  - `update_user_role(user_id, role) -> bool`
  - `count_admins(org_id) -> int`
  - `create_api_key(org_id, label, scopes) -> ApiKey`
  - `validate_api_key(key) -> ApiKey | None`
  - `revoke_api_key(key) -> bool`
  - `list_api_keys(org_id) -> list[ApiKey]`
  - `insert_event(org_id, entry) -> bool`
  - `query_events(org_id, **filters) -> list[Event]`
  - `count_events(org_id, **filters) -> int`
  - `get_event(org_id, event_id) -> Event | None`
  - `summary(org_id, **filters) -> dict`
  - `delete_old_events(days) -> int`
  - `close()`

**Файлы:** `cloud/storage.py` (новый).

**Тесты:** `test_storage_protocol.py` — проверка что оба backend
реализуют все методы.

### 0.2 SqliteStorage (рефакторинг текущего db.py)

**Что сделать:**
- Переименовать `Database` → `SqliteStorage`, реализует `Storage`.
- Вся логика текущего `db.py` переносится без изменений (уже работает,
  322 теста green).
- `check_same_thread=False` + lock остаются (для тестов).

**Файлы:** `cloud/db.py` → `cloud/storage_sqlite.py`.

**Тесты:** существующие `test_cloud_db.py` — все 20 тестов остаются green.

### 0.3 PostgresStorage (новая реализация)

**Что сделать:**
- `cloud/storage_postgres.py` — реализация `Storage` через `psycopg2`
  (синхронный, чтобы не переписывать весь код на async).
- Пул соединений (`psycopg2.pool.ThreadedConnectionPool`, min 1, max 10).
- Все запросы — parameterized (`%s`, не `%` форматирование).
- Схема идентична SQLite, но типы адаптированы:
  - `TEXT` → `TEXT` (UUID хранится как строка)
  - `INTEGER` (revoked) → `BOOLEAN`
  - `REAL` (created_at, received_at) → `DOUBLE PRECISION`
  - `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`
  - `TEXT` (args, redactions, detection, chain, approval) → `JSONB`
    (Postgres JSONB = индексируемый JSON, быстрее SQLite TEXT)
- Индексы те же: `events_org_ts`, `events_org_decision`.
- Доп. индекс: `events_org_seq_unique` — UNIQUE(org_id, seq) для
  idempotent insert (в SQLite проверяли SELECT, в Postgres —
  `ON CONFLICT (org_id, seq) DO NOTHING`).

**Файлы:** `cloud/storage_postgres.py` (новый).

**Тесты:** `test_storage_postgres.py` — те же 20 тестов что для SQLite,
через testcontainers-postgres (или skip если нет Postgres в CI).

### 0.4 Миграции (схема)

**Что сделать:**
- `cloud/migrations/` — SQL файлы:
  - `001_initial.sql` — создание всех таблиц (для Postgres).
  - `002_token_version.sql` — колонка `token_version` (Этап 2.3).
  - `003_dashboard_audit.sql` — таблица `dashboard_actions` (Этап 3.4).
  - `004_rate_limits.sql` — таблица `rate_limit_buckets` (Этап 4.2).
- При старте `server.py` — проверить `schema_migrations` таблицу,
  применить недостающие миграции.
- MVP: простой runner (не Alembic, чтобы не добавлять dep).

**Файлы:** `cloud/migrations/001_initial.sql`, `cloud/migrator.py`.

**Тесты:** `test_migrator.py` — чистая БД → миграция → все таблицы есть;
  повторный запуск → no-op.

### 0.5 Factory: переключение backend через env

**Что сделать:**
- `cloud/storage_factory.py`:
  ```python
  def create_storage() -> Storage:
      url = os.environ.get("DATABASE_URL") or os.environ.get("MCP_SHIELD_DB_URL")
      if url and url.startswith("postgres"):
          return PostgresStorage(url)
      return SqliteStorage(os.environ.get("MCP_SHIELD_DB_PATH", "mcp_shield_cloud.db"))
  ```
- `server.py` использует `create_storage()` вместо `Database(path)`.

**Файлы:** `cloud/storage_factory.py` (новый), `cloud/server.py`.

**Тесты:** `test_storage_factory.py` — `DATABASE_URL` задан →
  PostgresStorage; не задан → SqliteStorage.

### 0.6 Зависимости и Dockerfile

**Что сделать:**
- `pyproject.toml`: добавить `psycopg2-binary>=2.9` в `[cloud]` extra.
- `Dockerfile`: `pip install ".[cloud]"` уже установит psycopg2.
- `psycopg2-binary` включает libpq — не нужен system package.
- Для Railway: PostgreSQL plugin даёт `DATABASE_URL` автоматически.

**Файлы:** `pyproject.toml`, `Dockerfile` (без изменений).

### 0.7 Railway: добавление PostgreSQL

**Что сделать (manual, не код):**
1. Railway → Project → **New → Database → PostgreSQL**.
2. Railway создаёт `DATABASE_URL` variable автоматически.
3. Railway → сервис `mcp-shield-cloud` → **Variables** → **Add Variable**
   → `DATABASE_URL` = **Reference** к PostgreSQL plugin.
4. Удалить Volume `/app/data` (больше не нужен для SQLite).
5. Redeploy.

**Результат:** дашборд использует Postgres, SQLite — только для тестов.

---

## Этап 1 — Web-уязвимости (OWASP Top 10)

### 1.1 CSRF-защита для всех POST-форм
**Что не так:** формы `/login`, `/register`, `/users`, `/keys` без CSRF-токена.
**Риск:** атакующий заставляет админа отозвать ключ через `<form>` на другом сайте.
**Что сделать:** `CSRFMiddleware` генерирует токен (signed cookie + `request.state`); все POST-формы получают hidden input; middleware проверяет совпадение на POST → 403; GET exempt.
**Файлы:** `cloud/middleware.py` (новый), `cloud/server.py`, `cloud/dashboard.py`, шаблоны.
**Тесты:** `test_csrf.py` — POST без токена → 403; с верным → 200.

### 1.2 CORS для ingest API
**Что сделать:** `CORSMiddleware` с `allow_origins=["*"]` ТОЛЬКО для `/api/*`; для dashboard — запрещён.
**Файлы:** `cloud/server.py`.
**Тесты:** `test_cors.py` — OPTIONS на `/api/ingest` → 200; `/dashboard` с чужим Origin → нет ACAO.

### 1.3 Security headers middleware
**Что сделать:** `SecurityHeadersMiddleware` — X-Frame-Options, X-Content-Type-Options, HSTS (если `MCP_SHIELD_HTTPS=1`), Referrer-Policy, CSP.
**Файлы:** `cloud/middleware.py`, `cloud/server.py`.
**Тесты:** `test_security_headers.py`.

### 1.4 Cookie security flags
**Что сделать:** `secure=True` если `MCP_SHIELD_HTTPS=1`; `samesite="lax"` всегда; helper `_set_session_cookie()`.
**Файлы:** `cloud/dashboard.py`.
**Тесты:** `test_cookie_security.py`.

---

## Этап 2 — Аутентификация и сессии

### 2.1 Rate limit на /login
**Что сделать:** per-email + per-IP: 5 неудачных / 15 мин → 429 + lockout; per-IP 20/мин; delay после 3 неудач; логировать в `login_attempts` (миграция 005).
**Файлы:** `cloud/auth.py`, `cloud/dashboard.py`, миграция 005.
**Тесты:** `test_login_rate_limit.py`.

### 2.2 Rate limit на /register
**Что сделать:** per-IP: 3/час; captcha после 2 попыток; email verification (SMTP, опционально).
**Файлы:** `cloud/auth.py`, `cloud/dashboard.py`.
**Тесты:** `test_register_rate_limit.py`.

### 2.3 Session rotation (token_version)
**Что сделать:** колонка `token_version` (миграция 002); session payload включает её; mismatch → 401; инкремент при смене пароля/роли.
**Файлы:** `cloud/storage_*.py`, `cloud/auth.py`, `cloud/dashboard.py`.
**Тесты:** `test_session_rotation.py`.

### 2.4 Смена пароля
**Что сделать:** `/settings` GET/POST — форма (old, new, new_confirm); валидация (>= 12 символов, complexity, reject top-1000); `must_change_password` флаг для дефолтного админа; middleware редиректит пока True.
**Файлы:** `cloud/dashboard.py`, `cloud/storage_*.py`, `cloud/templates/settings.html`.
**Тесты:** `test_password_change.py`.

### 2.5 Сброс пароля
**Что сделать:** `/forgot` POST — reset token (uuid4, TTL 1 час) в `password_resets` (миграция 006), email; `/reset` GET/POST — смена, инвалидация token, инкремент `token_version`. Требует SMTP.
**Файлы:** `cloud/dashboard.py`, миграция 006, `cloud/email.py`, шаблоны.
**Тесты:** `test_password_reset.py`.

---

## Этап 3 — Авторизация и управление

### 3.1 Удаление пользователя
**Что сделать:** `/users/{id}/delete` POST (admin) — soft delete; нельзя удалить себя/последнего админа; инкремент `token_version`.
**Файлы:** `cloud/dashboard.py`, `cloud/storage_*.py`.
**Тесты:** `test_user_delete.py`.

### 3.2 Смена роли
**Что сделать:** `/users/{id}/role` POST (admin); запрет понизить себя; логировать в `dashboard_actions`.
**Файлы:** `cloud/dashboard.py`, `cloud/storage_*.py`.
**Тесты:** `test_user_role.py`.

### 3.3 API key scopes
**Что сделать:** колонка `scopes` (JSONB): `["ingest"]`, `["read"]`; выбор в UI; `/api/ingest` проверяет `"ingest"`; новый `/api/events` GET проверяет `"read"`; default = `["ingest"]`.
**Файлы:** `cloud/storage_*.py`, `cloud/api_ingest.py`, `cloud/templates/keys.html`.
**Тесты:** `test_api_key_scopes.py`.

### 3.4 Audit log для dashboard actions
**Что сделать:** таблица `dashboard_actions` (миграция 003); логировать все state-changing действия; `/audit` GET (admin).
**Файлы:** миграция 003, `cloud/storage_*.py`, `cloud/dashboard.py`, `cloud/templates/audit.html`.
**Тесты:** `test_dashboard_audit.py`.

---

## Этап 4 — Ingest API hardening

### 4.1 Валидация входных данных
**Что сделать:** pydantic model `IngestEntry` — типы, лимиты (args max 100KB, строки max 500); `_MAX_BODY_BYTES=1_000_000`; Jinja2 autoescape.
**Файлы:** `cloud/api_ingest.py`, `cloud/storage_*.py`.
**Тесты:** `test_ingest_validation.py`.

### 4.2 Persistent rate limiting
**Что сделать:** таблица `rate_limit_buckets` (миграция 004) в Postgres; очистка старых окон.
**Файлы:** миграция 004, `cloud/storage_*.py`, `cloud/api_ingest.py`.
**Тесты:** `test_persistent_rate_limit.py`.

### 4.3 API versioning
**Что сделать:** `/api/v1/ingest`; старый роут — alias (deprecated, warning header).
**Файлы:** `cloud/api_ingest.py`.
**Тесты:** `test_api_versioning.py`.

### 4.4 IP allowlist (опционально)
**Что сделать:** per-key `allowed_ips` (JSONB); проверка `request.client.host`.
**Файлы:** `cloud/storage_*.py`, `cloud/api_ingest.py`.
**Тесты:** `test_ip_allowlist.py`.

---

## Этап 5 — Данные и приватность

### 5.1 Data retention
**Что сделать:** env `MCP_SHIELD_RETENTION_DAYS` (default 90); background task — `DELETE FROM events WHERE received_at < now() - interval`.
**Файлы:** `cloud/storage_*.py`, `cloud/server.py`.
**Тесты:** `test_data_retention.py`.

### 5.2 GDPR: export и deletion
**Что сделать:** `/org/export` GET (admin) — ZIP; `/org/delete` POST (admin) — cascade delete, подтверждение "DELETE".
**Файлы:** `cloud/dashboard.py`, `cloud/storage_*.py`.
**Тесты:** `test_gdpr.py`.

### 5.3 Backup (Postgres)
**Что сделать:** Railway PostgreSQL имеет built-in backups; дополнительно `pg_dump` cron daily, 30 дней.
**Файлы:** `scripts/backup_pg.sh`.

---

## Этап 6 — Инфраструктура и мониторинг

### 6.1 Health check
**Что сделать:** `/health` GET — `SELECT 1`, event count; 200/503; без auth.
**Файлы:** `cloud/dashboard.py`.
**Тесты:** `test_health.py`.

### 6.2 Sentry
**Что сделать:** `sentry-sdk[fastapi]` (env `SENTRY_DSN`); без sensitive data.
**Файлы:** `cloud/server.py`, `pyproject.toml`.

### 6.3 Structured logging
**Что сделать:** JSON formatter; логировать method, path, status, latency, org_id; env `MCP_SHIELD_LOG_LEVEL`.
**Файлы:** `cloud/server.py`, `cloud/middleware.py`.

### 6.4 Request size limits
**Что сделать:** middleware — `Content-Length` max 2MB; ingest 1MB; forms 100KB.
**Файлы:** `cloud/middleware.py`, `cloud/server.py`.
**Тесты:** `test_request_limits.py`.

---

## Этап 7 — Прокси-side hardening

### 7.1 TLS verification в shipper
**Что сделать:** reject `http://` по умолчанию; `--cloud-ca-cert` для self-signed; env `MCP_SHIELD_ALLOW_HTTP_CLOUD=1` для dev.
**Файлы:** `shipper.py`.
**Тесты:** `test_shipper_tls.py`.

### 7.2 Local spool (disk buffer)
**Что сделать:** при неудаче flush — писать в `spool/pending_*.jsonl`; background thread ретраит; лимит 100MB.
**Файлы:** `shipper.py`, `mcp_shield/spool.py`.
**Тесты:** `test_spool.py`.

### 7.3 Graceful shutdown
**Что сделать:** SIGTERM handler → flush shipper → spool remaining → close subprocess → exit.
**Файлы:** `proxy.py`, `shipper.py`.
**Тесты:** `test_graceful_shutdown.py`.

---

## Этап 8 — Тестирование и CI

### 8.1 Security testing
**Что сделать:** OWASP ZAP в CI; fuzzing; pen-test чеклист.
**Файлы:** `tests/security/`, `.github/workflows/security.yml`.

### 8.2 Load testing
**Что сделать:** `locust` — 1000 events/sec; 100 concurrent users; p99 < 500ms.
**Файлы:** `tests/load/locustfile.py`.

### 8.3 GitHub Actions CI/CD
**Что сделать:** workflow на PR + push: `pytest`, `ruff`, `mypy`; auto-deploy main → Railway; pre-commit hooks.
**Файлы:** `.github/workflows/ci.yml`, `.pre-commit-config.yaml`.

---

## Сводка по приоритетам

| Этап | Задач | Время | Блокирует |
|---|---|---|---|
| 0. Postgres миграция | 7 | 6 дней | масштабирование |
| 1. Web-уязвимости | 4 | 3 дня | релиз |
| 2. Аутентификация | 5 | 7 дней | релиз |
| 3. Авторизация | 4 | 5 дней | релиз |
| 4. Ingest hardening | 4 | 4 дня | масштабирование |
| 5. Данные/приватность | 3 | 4 дня | GDPR |
| 6. Инфраструктура | 4 | 3 дня | мониторинг |
| 7. Прокси-side | 3 | 4 дня | надёжность |
| 8. Тестирование/CI | 3 | 3 дня | качество |
| **Итого** | **37** | **~39 дней** | |

**MVP для релиза** (~18 дней): этапы 0, 1, 2.1-2.4, 3.1, 3.4, 4.1, 6.1, 8.3.
**Полная security** (~39 дней): все 37 задач.
