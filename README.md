# Sentinel AI WAF / SOC M4 — Final Boss

개인용 웹 방화벽(WAF) + 보안관제(SOC) 플랫폼입니다. Cloudflare Workers를 웹 앞단에 두고, Rule Engine → Risk Score → 선택적 Workers AI → 자동 차단 → D1 이벤트 저장 → Durable Object 실시간 스트림으로 이어집니다.

## 무료 설계
- Workers Free 환경을 우선 대상으로 설계
- D1은 이벤트 저장소
- Workers AI는 의심 요청에만 호출
- Durable Objects는 실시간 SOC 스트림에 사용
- Rate Limiting binding을 추가할 수 있도록 확장 가능한 구조

Cloudflare의 무료 한도는 변경될 수 있으므로 배포 시 공식 문서를 확인하세요.

## 배포
1. GitHub repository에 이 폴더 전체를 업로드
2. Cloudflare Workers에서 GitHub repository 연결
3. D1 database 생성: `sentinel-db`
4. `wrangler.toml`의 `REPLACE_WITH_D1_ID`를 실제 database_id로 변경
5. `src/index.js` 또는 환경변수에서 `PROTECTED_ORIGIN`을 실제 origin으로 변경
6. `ADMIN_TOKEN` 같은 비밀값은 production에서는 Secret으로 관리
7. `npx wrangler d1 execute sentinel-db --remote --file=./db/schema.sql`
8. 배포: `npx wrangler deploy`

## 로컬
```bash
npm install
npm run check
npm run dev
```

## 운영 구조
```text
Internet → Cloudflare Worker/WAF → Origin
                 │
       ┌─────────┼──────────┐
       ▼         ▼          ▼
   Rule/Risk     AI        D1
       │                    │
       ▼                    ▼
  Allow/Review/Block     SOC Dashboard
                            ▲
                            │
                     Durable Object WS
```

## 주의
이 프로젝트는 방어용 보안 소프트웨어입니다. 실제 운영에서는 origin을 직접 노출하지 않고 Cloudflare를 통해서만 접근되도록 구성하고, 관리자 인증/Secrets/백업/보안정책을 별도로 강화하세요.
