# kong-fapi2

Kong Gateway を使った FAPI 2.0 検証環境です。

## 構成

```text
.
├── docker-compose.yaml          # Kong + Keycloak 環境
├── .env                         # 環境変数（gitignore 対象）
├── .env.default                 # .env のサンプル（コミット対象）
├── deck/
│   └── deck.yaml                # Kong Gateway 設定（decK）
├── keycloak/
│   └── realm-import/
│       └── fapi2-realm.json     # Keycloak realm 定義
└── scripts/
    └── dpop_e2e_verify.py       # FAPI 2.0 DPoP エンドツーエンド検証スクリプト
```

### テストユーザー

| ユーザー | パスワード | グループ |
| --- | --- | --- |
| alice | alice-pass | fapi2-users |
| bob | bob-pass | fapi2-users |
| charlie | charlie-pass | なし |

### Keycloak クライアント

| クライアントID | 用途 | PAR | PKCE | DPoP | PS256 |
| --- | --- | --- | --- | --- | --- |
| `kong` | Kong introspection 用サービスアカウント | - | - | - | - |
| `fapi2-test-client` | FAPI 2.0 テスト用（Authorization Code + PKCE + DPoP） | 必須 | 必須 (S256) | 必須 | ○ |

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

Keycloak の起動（ヘルスチェック通過）まで約 60 秒かかります。

### 3. decK による Kong 設定の適用

```bash
# .env の変数をシェルにエクスポートしてから deck を実行
set -a; source .env; set +a

deck gateway sync deck/deck.yaml
```

## エンドポイント

| サービス | URL |
| --- | --- |
| Kong Proxy | <http://localhost:8000> |
| Kong Admin API | <http://localhost:8001> |
| Kong Manager | <http://localhost:8002> |
| Keycloak Admin Console | <http://keycloak.localhost:9080> |
| Keycloak Admin ユーザー | admin / admin |

## エンドツーエンド検証（推奨）

PAR → Keycloak ログイン → DPoP バインドトークン取得 → Kong API 呼び出しまでを自動実行します。

```bash
python3 scripts/dpop_e2e_verify.py
```

`cryptography` と `requests` が必要です（`pip install cryptography requests`）。

## API テスト（手動）

`fapi2-test-client` は DPoP 必須です。`Authorization: DPoP` ヘッダーと `DPoP:` Proof ヘッダーの両方が必要です。

```bash
# DPoP Proof を生成してリクエスト（dpop-private.pem が必要）
# 詳細な手順は README.md を参照
curl http://localhost:8000/anything \
  -H "Authorization: DPoP <ACCESS_TOKEN>" \
  -H "DPoP: <DPOP_PROOF>"
```

## 環境の停止・削除

```bash
# 停止
docker compose down

# データを含めて削除
docker compose down -v
```
