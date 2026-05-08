# kong-fapi2

Kong Gateway を使った FAPI 2.0 検証環境です。**3 種類の検証構成**（Kong = RS / Kong = RP × `private_key_jwt` / Kong = RP × mTLS）を切り替えながら動かせます。詳細な仕様解説と検証手順は [README.md](README.md) を参照してください。

## 構成

```text
.
├── docker-compose.yaml             # Kong + Keycloak + Postgres × 2 + httpbin
├── .env                            # 環境変数（gitignore 対象）
├── .env.default                    # .env のサンプル（コミット対象）
├── deck/
│   ├── rs.yaml                     # 検証 1: Kong = RS（DPoP/mTLS 検証側）
│   ├── rp.yaml                     # 検証 2: Kong = RP（private_key_jwt + PAR + JAR + PKCE）
│   └── rp-mtls.yaml                # 検証 3: Kong = RP × mTLS（tls_client_auth + cert-bound token）
├── keycloak/
│   └── realm-import/
│       └── fapi2-realm.json        # Keycloak realm 定義（4 クライアント + 3 ユーザー）
├── keys/                           # 検証 2 用：Kong RP の PS256 鍵ペア / JWKS
│   ├── generate_jwks.py
│   ├── kong-rp-private.pem
│   ├── kong-rp-public.pem
│   ├── kong-rp-private.jwk.json
│   └── kong-rp-public.jwks.json
├── tls/                            # 検証 3 用：内部 CA + サーバー / クライアント証明書
│   ├── generate.sh                 # 証明書一式の再生成スクリプト
│   ├── ca-cert.pem / ca-key.pem    # PoC 用ローカル CA
│   ├── keycloak-cert.pem / -key.pem
│   └── kong-rp-mtls-cert.pem / -key.pem
└── scripts/
    ├── dpop_e2e_verify.py          # 検証 1 用（PAR → DPoP → API 呼び出し）
    ├── rp_e2e_verify.py            # 検証 2 用（Kong RP の認可コードフロー）
    └── rp_mtls_e2e_verify.py       # 検証 3 用（cnf.x5t#S256 一致まで確認）
```

### テストユーザー

| ユーザー | パスワード | グループ |
| --- | --- | --- |
| alice | alice-pass | fapi2-users |
| bob | bob-pass | fapi2-users |
| charlie | charlie-pass | なし |

### Keycloak クライアント

| クライアントID | 用途 | クライアント認証 | PAR | PKCE | DPoP | mTLS bound | 署名 alg |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `kong` | Kong introspection 用サービスアカウント | `client_secret` | - | - | - | - | - |
| `fapi2-test-client` | 検証 1（RS）：FAPI 2.0 Authorization Code + PKCE + DPoP | `client_secret_post` | 必須 | 必須 (S256) | 必須 | - | PS256 |
| `kong-rp-client` | 検証 2（RP / pkjwt）：Kong が PS256 鍵で client_assertion 署名 | `private_key_jwt` | 必須 | 必須 (S256) | - | - | PS256 |
| `kong-rp-mtls-client` | 検証 3（RP × mTLS）：Kong が X.509 クライアント証明書で認証 | `tls_client_auth` | 必須 | 必須 (S256) | - | 必須 | PS256 |

## セットアップ

### 1. 環境変数の準備

```bash
cp .env.default .env
# 必要に応じて .env を編集（KONG_LICENSE_DATA など）
```

### 2. 環境の起動

```bash
docker compose up -d
```

Keycloak の起動（ヘルスチェック通過）まで約 60 秒かかります。Docker Desktop のメモリ割り当ては **6GB 以上** を推奨（Keycloak の OOM 落ちを避けるため）。

### 3. decK による Kong 設定の適用

検証する構成に応じて適用する deck ファイルを切り替えます。**3 つを同時に動かす想定はありません**（同じ Keycloak realm を共用しつつ、Kong に投入する設定だけ差し替える運用）。

```bash
# .env の変数をシェルにエクスポートしてから deck を実行
set -a; source .env; set +a

# 検証 1: Kong = RS
deck gateway sync deck/rs.yaml

# 検証 2: Kong = RP（private_key_jwt）
deck gateway sync deck/rp.yaml

# 検証 3: Kong = RP × mTLS
deck gateway sync deck/rp-mtls.yaml
```

## エンドポイント

| サービス | URL |
| --- | --- |
| Kong Proxy（HTTP） | <http://localhost:8000> |
| Kong Proxy（HTTPS） | <https://localhost:8443> |
| Kong Admin API（HTTP） | <http://localhost:8001> |
| Kong Admin API（HTTPS） | <https://localhost:8444> |
| Kong Manager | <http://localhost:8002> |
| Keycloak（HTTP） | <http://keycloak.localhost:9080> |
| **Keycloak（HTTPS+mTLS）** | <https://keycloak.localhost:9443>（検証 3 で使用、`mtls_endpoint_aliases` 経由） |
| Keycloak Admin ユーザー | admin / admin |

## エンドツーエンド検証

それぞれの検証構成を一気通貫で確認するスクリプトを用意しています。事前に対応する `deck gateway sync` を済ませてから実行してください。

```bash
# 検証 1: PAR → Keycloak ログイン → DPoP バインドトークン取得 → Kong API 呼び出し
python3 scripts/dpop_e2e_verify.py

# 検証 2: Kong = RP として PAR + JAR + private_key_jwt で認可コードフローを完走
python3 scripts/rp_e2e_verify.py

# 検証 3: Kong = RP × mTLS で cnf.x5t#S256 一致まで実証
python3 scripts/rp_mtls_e2e_verify.py
```

`cryptography` と `requests` が必要です（`pip install cryptography requests`）。

## API テスト（手動）

検証 1 の `fapi2-test-client` は DPoP 必須です。`Authorization: DPoP` ヘッダーと `DPoP:` Proof ヘッダーの両方が必要です。

```bash
# DPoP Proof を生成してリクエスト（dpop-private.pem が必要）
# 詳細な手順は README.md を参照
curl http://localhost:8000/anything \
  -H "Authorization: DPoP <ACCESS_TOKEN>" \
  -H "DPoP: <DPOP_PROOF>"
```

検証 2 / 3 はブラウザでアクセスする想定です（Kong がセッション Cookie を発行）。

```bash
# 検証 2
open http://localhost:8000/protected

# 検証 3
open http://localhost:8000/protected-mtls
```

## 環境の停止・削除

```bash
# 停止
docker compose down

# データを含めて削除（realm の再投入を行いたい場合）
docker compose down -v
```
