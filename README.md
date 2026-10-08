# SENTINEL AI WAF / SOC M5

개인용 Cloudflare Workers 기반 AI WAF + SOC입니다. **Free-first**를 목표로 만들었으며 D1, Durable Objects, Workers AI를 사용합니다.

## M5 핵심 변경

- 실제 D1 ID 연결 완료: `6ff6663b-54ed-47b0-a9e3-0bb4424b3723`
- 관리자 API 인증: `ADMIN_TOKEN` Secret
- SOC WebSocket Hibernation 구조 수정
- Durable Object broadcast를 `fetch()` 내부 경로로 수정
- SQLi / XSS / Traversal / Command Injection / Scanner / Sensitive Path / Encoding 탐지
- isolate-local burst rate limiting + 선택적 Cloudflare Rate Limiting binding 지원
- 공격자 프로필 / strike / 자동 ban escalation
- campaign correlation / incidents
- blocklist / allowlist
- D1 이벤트 저장 및 조회
- 대시보드 출력 escaping으로 저장형 XSS 방어
- 보안 헤더 추가
- Threat Lab
- GitHub Actions 자동 배포 파이프라인

## 중요: 기존 M4 D1을 사용하는 경우

네 D1 `sentinel-db`가 M4에서 이미 만들어졌다면 `schema.sql`만 다시 실행하면 기존 테이블이 그대로 유지되어 새 컬럼이 생기지 않습니다.

따라서 M5 ZIP의 다음 파일을 **한 번만** 실행하세요:

```bash
npx wrangler d1 execute sentinel-db --remote --file=./db/migrate-m4-to-m5.sql
```

만약 D1을 새로 만든 상태라면:

```bash
npx wrangler d1 execute sentinel-db --remote --file=./db/schema.sql
```

## 관리자 토큰

민감한 관리자 토큰은 `wrangler.toml`에 넣지 않습니다.

```bash
npx wrangler secret put ADMIN_TOKEN
```

입력창에 긴 랜덤 토큰을 넣습니다. Cloudflare도 비밀번호/API 토큰 같은 민감값은 `vars` 대신 Secret으로 저장하도록 권장합니다.

## 보호할 원본 사이트

`wrangler.toml`의:

```toml
PROTECTED_ORIGIN = "https://example.com"
```

을 실제 원본 서버 주소로 바꿉니다.

예:

```toml
PROTECTED_ORIGIN = "https://origin.example.com"
```

M5는 placeholder가 남아 있으면 public traffic을 원본으로 보내지 않고 503을 반환합니다. 실수로 WAF 우회가 생기는 것을 막기 위한 안전장치입니다.

## 배포

```bash
npm install
npx wrangler deploy
```

배포 후 `/` 또는 `/soc`에서 SOC 화면을 열고 관리자 토큰을 입력합니다.

## GitHub 자동 배포

GitHub repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

를 추가하면 `.github/workflows/deploy.yml`이 `main` push 때 테스트 → syntax check → deploy를 수행합니다.

## 선택적 Cloudflare Rate Limiting

추가 설정 없이도 M5에는 Worker isolate-local burst limiter가 있습니다. 더 강한 분산 rate limiting을 사용하려면 Cloudflare Rate Limiting namespace를 만든 후 `wrangler.toml`의 주석 블록을 활성화하고 고유한 숫자 `namespace_id`를 넣습니다. Cloudflare Rate Limiting binding은 `limit`과 `period`를 사용하며 period는 10초 또는 60초입니다.

## 보안 운영 주의

- 관리자 토큰은 절대 GitHub에 commit하지 마세요.
- 원본 서버가 Worker를 우회해 직접 노출되지 않게 하세요.
- 실제 서비스에서는 Cloudflare Access/Tunnel/네트워크 방화벽 등으로 origin을 보호하는 것을 권장합니다.
- M5는 개인용/학습용 방어 계층이며 모든 공격을 탐지한다고 보장하지 않습니다.
