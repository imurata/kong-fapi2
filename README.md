Kong Gateway を使った FAPI 2.0の検証

## 目次

- [目次](#目次)
- [FAPIとは](#fapiとは)
  - [概要](#概要)
  - [FAPI 2.0 の特徴](#fapi-20-の特徴)
    - [FAPI 2.0 Security Profile](#fapi-20-security-profile)
    - [FAPI 2.0 Message Signing](#fapi-20-message-signing)
      - [3 つの option それぞれの概要](#3-つの-option-それぞれの概要)
        - [① Signed Authorization Requests（JAR）](#-signed-authorization-requestsjar)
        - [② Signed Authorization Responses（JARM）](#-signed-authorization-responsesjarm)
        - [③ Signed Introspection Responses（RFC 9701）](#-signed-introspection-responsesrfc-9701)
      - [conformance testing option とは](#conformance-testing-option-とは)
    - [FAPI 2.0 Security Profileと Message Signing を組み合わせた場合の処理](#fapi-20-security-profileと-message-signing-を組み合わせた場合の処理)
    - [実装チェックリスト](#実装チェックリスト)
      - [クライアント（RP）](#クライアントrp)
      - [認可サーバー（Keycloak）](#認可サーバーkeycloak)
      - [リソースサーバー（Kong Gateway）](#リソースサーバーkong-gateway)
  - [FAPI 2.0 の対応状況](#fapi-20-の対応状況)
    - [機能対応・認証取得状況](#機能対応認証取得状況)
    - [各 IdP の補足](#各-idp-の補足)
- [FAPI の沿革](#fapi-の沿革)
  - [FAPI 1.0 リリースまで](#fapi-10-リリースまで)
  - [FAPI 2.0 リリースまで](#fapi-20-リリースまで)
  - [FAPI 1.0と2.0の相違点](#fapi-10と20の相違点)
- [付録 - 用語解説](#付録---用語解説)
  - [RS256/ES256/PS256/S256/RSA-PSS/楕円曲線署名](#rs256es256ps256s256rsa-pss楕円曲線署名)
    - [署名アルゴリズム（JWT の `alg` クレームで指定）](#署名アルゴリズムjwt-の-alg-クレームで指定)
    - [RSA-PSS とは](#rsa-pss-とは)
    - [楕円曲線署名（ECDSA）とは](#楕円曲線署名ecdsaとは)
    - [S256（PKCE のコード検証方式）](#s256pkce-のコード検証方式)
    - [まとめ](#まとめ)
  - [PKCE（Proof Key for Code Exchange）](#pkceproof-key-for-code-exchange)
    - [何が問題だったか](#何が問題だったか)
    - [どうやって解決したか](#どうやって解決したか)
    - [PKCEの仕組み](#pkceの仕組み)
    - [S256 が必須な理由](#s256-が必須な理由)
    - [code\_challenge の保存期間](#code_challenge-の保存期間)
  - [PAR（Pushed Authorization Requests）](#parpushed-authorization-requests)
  - [JAR（JWT Secured Authorization Requests）](#jarjwt-secured-authorization-requests)
  - [JARM（JWT Secured Authorization Response Mode）](#jarmjwt-secured-authorization-response-mode)
  - [Signed Introspection Responses（RFC 9701）](#signed-introspection-responsesrfc-9701)
    - [通常の introspection との違い](#通常の-introspection-との違い)
    - [Signed Introspection Responses の仕組み](#signed-introspection-responses-の仕組み)
    - [何が嬉しいか](#何が嬉しいか)
    - [FAPI 2.0 における位置づけ](#fapi-20-における位置づけ)
    - [Kong Gateway での対応状況](#kong-gateway-での対応状況)
  - [Sender-constrained Access Token と DPoP / mTLS](#sender-constrained-access-token-と-dpop--mtls)
    - [Kong Gateway がそれぞれの方式で担う役割](#kong-gateway-がそれぞれの方式で担う役割)
  - [DPoP（Demonstrating Proof of Possession）](#dpopdemonstrating-proof-of-possession)
    - [公開鍵の伝達方法](#公開鍵の伝達方法)
    - [フロー](#フロー)
  - [mTLS Sender-constrained Access Token（RFC 8705）](#mtls-sender-constrained-access-tokenrfc-8705)
    - [トークンへのバインド方法](#トークンへのバインド方法)
    - [API 呼び出し時の検証](#api-呼び出し時の検証)
    - [DPoP 方式との実装上の違い](#dpop-方式との実装上の違い)
    - [mTLS 方式での Kong Gateway の役割](#mtls-方式での-kong-gateway-の役割)
- [API Gateway の FAPI 2.0 対応状況比較](#api-gateway-の-fapi-20-対応状況比較)
  - [補足](#補足)
- [Kong Gateway での実装例](#kong-gateway-での実装例)
  - [FAPI 2.0 における Kong Gateway の役割](#fapi-20-における-kong-gateway-の役割)
    - [FAPI 2.0 における RP の配置パターン](#fapi-20-における-rp-の配置パターン)
      - [なぜブラウザ／SPA を RP にしないのか](#なぜブラウザspa-を-rp-にしないのか)
      - [配置パターン比較](#配置パターン比較)
    - [Kong Gateway が担える2つの役割（RS / RP）](#kong-gateway-が担える2つの役割rs--rp)
    - [本リポジトリの位置づけ](#本リポジトリの位置づけ)
      - [検証 1（Kong = RS）の補足](#検証-1kong--rsの補足)
      - [検証 2（Kong = RP）の補足](#検証-2kong--rpの補足)
        - [Kong の openid-connect プラグインの限界（FAPI 2.0 RP として）](#kong-の-openid-connect-プラグインの限界fapi-20-rp-として)
      - [検証 3（Kong = RP × mTLS）の補足](#検証-3kong--rp--mtlsの補足)
    - [Kong を RS として使う場合のフロー](#kong-を-rs-として使う場合のフロー)
    - [Kong を RP として使う場合のフロー](#kong-を-rp-として使う場合のフロー)
      - [シーケンス図](#シーケンス図)
      - [openid-connect プラグインの RP モード設定例](#openid-connect-プラグインの-rp-モード設定例)
      - [適しているシナリオ](#適しているシナリオ)
      - [運用上の注意点](#運用上の注意点)
  - [openid-connect プラグインの FAPI 対応機能](#openid-connect-プラグインの-fapi-対応機能)
  - [「FAPI 2.0 対応」と言えるか](#fapi-20-対応と言えるか)
    - [立場別：conformance test との関わり方](#立場別conformance-test-との関わり方)
      - [自社実装する場合の流れ（参考）](#自社実装する場合の流れ参考)
  - [検証 1: Kong = RS](#検証-1-kong--rs)
    - [検証 1 の構成](#検証-1-の構成)
    - [検証 1 の環境起動](#検証-1-の環境起動)
      - [1. `.env` ファイルを準備する](#1-env-ファイルを準備する)
      - [2. Docker Compose で全サービスを起動する](#2-docker-compose-で全サービスを起動する)
      - [3. Keycloak の起動を確認する](#3-keycloak-の起動を確認する)
      - [4. deck で Kong に RS 設定を反映する](#4-deck-で-kong-に-rs-設定を反映する)
    - [検証 1 自動検証スクリプト](#検証-1-自動検証スクリプト)
    - [検証 1 正常系：FAPI 2.0 フローの実行（手動）](#検証-1-正常系fapi-20-フローの実行手動)
      - [5. DPoP 用の EC キーペアを生成する](#5-dpop-用の-ec-キーペアを生成する)
      - [6. PAR エンドポイントにリクエストして `request_uri` を取得する](#6-par-エンドポイントにリクエストして-request_uri-を取得する)
      - [7. ブラウザで認可エンドポイントにアクセスしてログインし、認可コードを取得する](#7-ブラウザで認可エンドポイントにアクセスしてログインし認可コードを取得する)
        - [インターネットに接続できる環境の場合（`redirect_uri=https://openidconnect.net/callback`）](#インターネットに接続できる環境の場合redirect_urihttpsopenidconnectnetcallback)
        - [インターネット接続が制限されている環境の場合](#インターネット接続が制限されている環境の場合)
      - [8. DPoP Proof JWT を生成し、トークンエンドポイントで認可コードを交換する](#8-dpop-proof-jwt-を生成しトークンエンドポイントで認可コードを交換する)
      - [9. Kong 経由でバックエンド API を呼び出す](#9-kong-経由でバックエンド-api-を呼び出す)
    - [検証 1 異常系：拒否されることを確認する](#検証-1-異常系拒否されることを確認する)
      - [10. DPoP Proof なしでアクセスする → 401 を確認する](#10-dpop-proof-なしでアクセスする--401-を確認する)
      - [11. PAR なしで認可エンドポイントに直接アクセスする → Keycloak が拒否することを確認する](#11-par-なしで認可エンドポイントに直接アクセスする--keycloak-が拒否することを確認する)
      - [12. グループ未所属の charlie のトークンで Kong にアクセスする](#12-グループ未所属の-charlie-のトークンで-kong-にアクセスする)
  - [検証 2: Kong = RP](#検証-2-kong--rp)
    - [検証 2 の構成](#検証-2-の構成)
    - [検証 2 の環境起動](#検証-2-の環境起動)
      - [1. Kong に RP 設定を反映する](#1-kong-に-rp-設定を反映する)
      - [2. ルートが投入されたことを確認する](#2-ルートが投入されたことを確認する)
    - [検証 2 自動検証スクリプト](#検証-2-自動検証スクリプト)
    - [検証 2 ブラウザでの手動確認](#検証-2-ブラウザでの手動確認)
      - [1. ブラウザで `/protected` にアクセスする](#1-ブラウザで-protected-にアクセスする)
      - [2. alice / alice-pass でログインする](#2-alice--alice-pass-でログインする)
      - [3. Kong からのレスポンスを確認する](#3-kong-からのレスポンスを確認する)
      - [4. Cookie を確認する](#4-cookie-を確認する)
      - [5. ログアウト](#5-ログアウト)
  - [検証 3: Kong = RP × mTLS](#検証-3-kong--rp--mtls)
    - [検証 3 の構成](#検証-3-の構成)
    - [検証 3 の環境起動](#検証-3-の環境起動)
      - [1. Kong に mTLS 用 RP 設定を反映する](#1-kong-に-mtls-用-rp-設定を反映する)
      - [2. mTLS ルートが投入されたことを確認する](#2-mtls-ルートが投入されたことを確認する)
    - [検証 3 自動検証スクリプト](#検証-3-自動検証スクリプト)
      - [各ステップの確認事項](#各ステップの確認事項)
    - [検証 3 で押さえている FAPI 2.0 要件](#検証-3-で押さえている-fapi-20-要件)
- [付録 - Kong Gateway と Keycloak の設定解説](#付録---kong-gateway-と-keycloak-の設定解説)
  - [Kong Gateway（deck/rs.yaml）](#kong-gatewaydeckrsyaml)
    - [openid-connect プラグイン](#openid-connect-プラグイン)
    - [Consumer とグループ](#consumer-とグループ)
  - [Kong Gateway（deck/rp.yaml）](#kong-gatewaydeckrpyaml)
    - [auth\_methods と redirect\_uri](#auth_methods-と-redirect_uri)
    - [private\_key\_jwt 認証](#private_key_jwt-認証)
    - [PAR / JAR / PKCE](#par--jar--pkce)
    - [内部 URL と公開 URL の混在](#内部-url-と公開-url-の混在)
    - [セッション設定](#セッション設定)
    - [Backend へのユーザー情報伝達](#backend-へのユーザー情報伝達)
  - [Kong Gateway（deck/rp-mtls.yaml）](#kong-gatewaydeckrp-mtlsyaml)
    - [Certificate エンティティ](#certificate-エンティティ)
    - [tls\_client\_auth でのクライアント認証](#tls_client_auth-でのクライアント認証)
    - [HTTPS+mTLS エンドポイントへの接続](#httpsmtls-エンドポイントへの接続)
    - [Kong コンテナ側の TLS 信頼設定](#kong-コンテナ側の-tls-信頼設定)
  - [Keycloak（fapi2-realm.json）](#keycloakfapi2-realmjson)
    - [Realm レベルの設定](#realm-レベルの設定)
    - [fapi2-test-client の設定](#fapi2-test-client-の設定)
    - [kong クライアントの設定](#kong-クライアントの設定)
    - [kong-rp-client の設定（検証 2 用）](#kong-rp-client-の設定検証-2-用)
    - [kong-rp-mtls-client の設定（検証 3 用）](#kong-rp-mtls-client-の設定検証-3-用)
    - [Realm 全体の HTTPS / mTLS 設定（docker-compose.yaml 側）](#realm-全体の-https--mtls-設定docker-composeyaml-側)
    - [Protocol Mapper（groups クレーム）](#protocol-mappergroups-クレーム)
- [付録 - 検証中に判明した注意点](#付録---検証中に判明した注意点)
  - [共通：Docker / Keycloak のホスト周り](#共通docker--keycloak-のホスト周り)
    - [Docker Desktop のメモリ割り当て](#docker-desktop-のメモリ割り当て)
    - [Keycloak の内部 / 外部 URL の統一](#keycloak-の内部--外部-url-の統一)
  - [検証 1（Kong = RS）で踏んだ注意点](#検証-1kong--rsで踏んだ注意点)
    - [Python `requests` の `.localhost` Cookie 問題](#python-requests-の-localhost-cookie-問題)
    - [charlie の認可テストは「期待通り 401」とは限らない](#charlie-の認可テストは期待通り-401とは限らない)
  - [検証 2（Kong = RP）で踏んだ注意点](#検証-2kong--rpで踏んだ注意点)
    - [YAML 1.1 の boolean 暗黙変換（`n:` が `false` になる）](#yaml-11-の-boolean-暗黙変換n-が-false-になる)
    - [Kong プラグイン側のキー名は `jwks_endpoint`](#kong-プラグイン側のキー名は-jwks_endpoint)
    - [DPoP の RP 側生成は未対応](#dpop-の-rp-側生成は未対応)
    - [JARM（`response_mode: query.jwt`）も Kong RP では未到達](#jarmresponse_mode-queryjwtも-kong-rp-では未到達)
    - [`proof_of_possession_auth_methods_validation: false` が必要なケース](#proof_of_possession_auth_methods_validation-false-が必要なケース)
  - [検証 3（Kong = RP × mTLS）で踏んだ注意点](#検証-3kong--rp--mtlsで踏んだ注意点)
    - [Kong Admin API は `id` フィールドに UUID v4 を要求する](#kong-admin-api-は-id-フィールドに-uuid-v4-を要求する)
    - [`tls_client_auth_cert_id` は文字列（配列ではない）](#tls_client_auth_cert_id-は文字列配列ではない)
    - [Keycloak 26 の PKCS12 トラストストア（`KC_HTTPS_TRUST_STORE_FILE`）は PoC で動かなかった](#keycloak-26-の-pkcs12-トラストストアkc_https_trust_store_fileは-poc-で動かなかった)
    - [Kong の Lua cosocket は OS 信頼ストアを参照しない](#kong-の-lua-cosocket-は-os-信頼ストアを参照しない)
    - [`x509.subjectdn` の厳密一致は外しやすい](#x509subjectdn-の厳密一致は外しやすい)
    - [コンテナ初回起動直後の JWKS キャッシュタイミング](#コンテナ初回起動直後の-jwks-キャッシュタイミング)
- [付録 - FAPI 認定（Conformance Certification）の取得方法](#付録---fapi-認定conformance-certificationの取得方法)
  - [認定の方式：self-certification](#認定の方式self-certification)
  - [テスト環境](#テスト環境)
  - [取得手順（OP の場合）](#取得手順op-の場合)
  - [費用（per new deployment）](#費用per-new-deployment)
  - [認定の単位（再掲）](#認定の単位再掲)
  - [エコシステム認定との関係](#エコシステム認定との関係)
  - [関連リソース](#関連リソース)

---

## FAPIとは
### 概要
FAPI（Financial-grade API）は、OpenID Foundation が策定した高セキュリティ API のセキュリティプロファイル（既存の標準仕様に対して「何を追加で守らなければならないか」を定めた上位仕様）である。OAuth 2.0 / OpenID Connect を基盤としつつ、金融サービスのような高度なセキュリティ要件を持つ API 向けに、より厳格な要件を追加定義している。



主な採用事例を以下に示す。

| 地域 | 規格・フレームワーク | ステータス |
| --- | --- | --- |
| 英国 | [Open Banking Security Profile](https://standards.openbanking.org.uk/security-profiles/) | FAPI 1.0 Advanced を正式採用 |
| EU | [Berlin Group NextGenPSD2](https://www.berlin-group.org/nextgenpsd2-downloads) | PSD2 準拠フレームワークに FAPI を統合 |
| ブラジル | [Open Finance Brasil Security Profile](https://openfinancebrasil.atlassian.net/wiki/spaces/OF/pages/1675395089/) | FAPI 1.0 Advanced を正式採用（独自拡張あり） |
| オーストラリア | [CDR Security Profile](https://consumerdatastandardsaustralia.github.io/infosec/) | Consumer Data Right にて FAPI 1.0 Advanced を正式採用 |
| 日本 | [全国銀行協会 オープン API ガイドライン](https://www.zenginkyo.or.jp/) | FAPI を参照・検討中（義務化はされていない） |

### FAPI 2.0 の特徴

FAPI 2.0 は **Security Profile** と **Message Signing** の2つのプロファイルで構成される。

#### FAPI 2.0 Security Profile

認可フロー全体に関する要件を定めた基盤プロファイルである。このプロファイル単体で、FAPI 1.0 Advanced と同等以上のセキュリティ強度が得られるよう設計されている。以降の説明では以下の略称を使用する。

- **AS**（Authorization Server＝認可サーバー）: トークンを発行する役割。本環境では Keycloak が該当する。
- **RS**（Resource Server＝リソースサーバー）: API を保護する役割。通常はバックエンド API サーバー自身が担うが、Kong Gateway のような API ゲートウェイを導入する場合はゲートウェイが RS として機能する。
- **Client**（OAuth 2.0 用語） / **RP**（OIDC 用語、Relying Party）: AS にトークンを要求し、RS が保護するリソースにアクセスする主体。OAuth 2.0 では「Client」、OIDC では「RP（Relying Party）」と呼ぶが、FAPI 2.0 はどちらの用語も同じ意味で使う。本ドキュメントでは原則 **RP** と表記する。RP の実体はモバイルアプリ・SPA・サーバーサイドの Web アプリ・BFF（Backend for Frontend）など様々で、誰が RP になるかが FAPI 2.0 の設計上の重要な選択肢になる（後述の [FAPI 2.0 における RP の配置パターン](#fapi-20-における-rp-の配置パターン)）。Kong Gateway も `openid-connect` プラグインを使えば RP として動作できる。
- **リソースオーナー**（Resource Owner）: 保護されたリソースの所有者。本環境ではエンドユーザー（alice 等）が該当する。RP に対してリソースへのアクセスを許可する主体である。

| カテゴリ | 要件 | 説明 |
| --- | --- | --- |
| 認可フロー | Authorization Code Flow のみ | Implicit Flow・ハイブリッドフローは禁止 |
| PKCE | 必須（S256 のみ） | コード横取り攻撃（Authorization Code Interception Attack）を防ぐ |
| PAR | 必須 | 認可リクエストのパラメータをブラウザ URL に露出させない（[RFC 9126](https://www.rfc-editor.org/rfc/rfc9126)） |
| sender-constrained token | DPoP または mTLS（必須） | AS は必ず sender-constrained なアクセストークン（＝**発行先クライアントの鍵 / 証明書に紐付き、それを持たない第三者には使えない**アクセストークン）を発行しなければならない。クライアントの鍵に紐付けることでトークン窃取時の再利用を防ぐ |
| クライアント認証 | `private_key_jwt` または mTLS | 共有シークレットによる認証（`client_secret_basic` 等）は禁止 |
| `response_type` | `code` のみ | トークンをブラウザに直接渡すフローをすべて排除 |
| JWT 署名アルゴリズム | PS256、ES256、または EdDSA | JWT を作成・検証する箇所で使用可能なアルゴリズム。RS256 は不可 |
| 認可コード有効期間 | 最大 60 秒 | 認可コードの短命化によりコード傍受リスクを低減（FAPI 2.0 仕様要件） |
| アクセストークン有効期間 | 短命を推奨（実装上の推奨） | FAPI 2.0 仕様の明示的な必須要件ではないが、長期有効なトークンの流出リスクを低減するための実装推奨事項である |
| `nonce` | OIDC をサポートする AS では最大 64 文字まで対応必須 | **nonce は「一度限りの値（number used once）」** という意味で、RP が認可リクエストに付けて送り、AS は発行する **ID Token（JWT）の `nonce` クレーム** に同じ値をコピーして返す。RP は受け取った ID Token の `nonce` が自分が送ったものと一致するかを検証することで、**過去のレスポンスの再生（リプレイ）を検知** できる。FAPI 2.0 では front-channel で ID Token を直接受け取るフロー（implicit/hybrid）を排除しているため FAPI 1.0 ほど中心的役割ではないが、OIDC をサポートする AS は 64 文字までの nonce を受け付けなければならない |

#### FAPI 2.0 Message Signing

Security Profile に加えて、**リクエスト・レスポンスそのものに署名**を施す要件を定めたプロファイルである。主な目的は認可リクエスト・レスポンスの integrity（完全性）の保証や、署名付き PAR リクエスト（JAR）と合わせた否認不可（non-repudiation）のユースケースを支えることである。

重要な点として、Message Signing 仕様は **3 つの独立した conformance option** で構成されており、実装はこれらを任意の組み合わせで採用できる。「Message Signing に準拠するなら全部必須」ではない。仕様 §5.1 は "We understand that some ecosystems may only desire to implement 1, 2 or 3 of the above" と述べており、エコシステムが必要な option だけを選んで実装することを想定している。

なお仕様は「最低 1 つ必須」と明示してはいないが、**「Message Signing 準拠」を主張するためには 3 つの option のうち少なくとも 1 つを実装している必要がある** と理解するのが実務上の整理である。0 個実装した状態では「Message Signing 準拠」を主張する実体的根拠がなく、Security Profile 準拠のみの状態と同等になる。

| Conformance option | 関連技術 | 説明 |
| --- | --- | --- |
| Signed Authorization Requests | JAR（[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101)） | 認可リクエスト全体を JWT として署名する。このオプションを選択した場合は AS・RP ともに JAR を実装すること |
| Signed Authorization Responses | JARM | 認可レスポンス（認可コード等）を JWT として署名して返す。このオプションを選択した場合は AS は JARM を実装し、RP は `response_mode=jwt` で受け取ること |
| Signed Introspection Responses | RFC 9701（OAuth 2.0 JWT Secured Introspection Response） | Introspection エンドポイントのレスポンスを署名付き JWT で返す。RS が AS の introspection 結果を信頼する経路に TLS 終端プロキシ等の中継が入る場合の改ざん防止、および監査証跡（AS が確かにこの内容を返したことの否認不可）を目的とする。詳細は [付録 - Signed Introspection Responses](#signed-introspection-responsesrfc-9701) を参照 |

##### 3 つの option それぞれの概要

各 option が「何を署名するのか」「どんな脅威を防ぐのか」を、具体的なやりとりに即して整理する。

###### ① Signed Authorization Requests（JAR）

**何を署名するのか**: 認可リクエストのパラメータ（`client_id`・`redirect_uri`・`scope`・`state`・`code_challenge` 等）を JWT としてまとめ、**RP（クライアント）の秘密鍵** で署名する。これを Request Object と呼び、PAR エンドポイントへ `request=＜署名済み JWT＞` の形で送る。

**何を防ぐのか**: PAR と組み合わせることで、認可リクエストの内容を **AS まで一切改ざんされずに到達する** ことを保証する。PAR 単体ではパラメータがバックチャネルで送られるとはいえ、AS 側で「このリクエストを送ったのは確かにこの RP である」と暗号学的に証明する手段がない。JAR を加えることで AS は「このリクエストは確かにこの RP の秘密鍵で署名された」と検証でき、リクエスト内容の完全性とリクエスト自体の送信者性（non-repudiation）が担保される。

**実装の例**: 「振込先口座番号を含む認可リクエスト」のような、改ざんされると深刻な被害が出るシナリオで価値が出る。詳細は [付録: JAR](#jarjwt-secured-authorization-requests) を参照。

###### ② Signed Authorization Responses（JARM）

**何を署名するのか**: 認可レスポンス（`code`・`state`・`iss`・`exp`）を **AS の秘密鍵** で署名した JWT として返す。通常は `?code=xxx&state=yyy` の形でクエリに平文で乗るが、JARM では `?response=＜署名済み JWT＞` の1パラメータに集約される。

**何を防ぐのか**: 主に **Mix-Up 攻撃**（複数の AS を扱うクライアントに対して、攻撃者が別の AS のレスポンスをすり替える攻撃）を防ぐ。JWT 内の `iss` クレームを検証することで「このレスポンスは確かに自分が認可リクエストを送った AS から返ってきた」と確認できる。また、レスポンスの URL 改ざんも検知できる。

**FAPI 2.0 Security Profile では不要な理由**: §5.5 で述べられている通り、`response_type=code` のみに限定し認可レスポンスを認可コードだけに絞ったため、レスポンスの integrity 保護そのものが obsolete になった。JARM が必要になるのは Message Signing でこの option を選択した場合のみ。詳細は [付録: JARM](#jarmjwt-secured-authorization-response-mode) を参照。

###### ③ Signed Introspection Responses（RFC 9701）

**何を署名するのか**: RS が AS の `/introspect` エンドポイントを叩いてアクセストークンの状態（`active`・`sub`・`scope`・`exp`・`cnf` 等）を確認するとき、AS が返す JSON レスポンスを **AS の秘密鍵** で署名した JWT として返す。RS は `Accept: application/token-introspection+jwt` ヘッダーをリクエストに付けて署名付きレスポンスを要求する。

**何を防ぐのか**: 通常の introspection レスポンスは TLS で守られているが、AS と RS の間に **TLS 終端プロキシ・WAF・サービスメッシュ等の中継ノード** が挟まる場合、TLS は中継ノードで一旦終端されるためレスポンス本文を改ざんされる余地がある。たとえば `"active": false` を `"active": true` に書き換えたり `"scope"` を昇格させたりするリプレイ・改ざんが理論上可能。Signed Introspection Responses はこれを暗号学的に防ぐ。さらに **監査証跡**（AS が確かにこの内容を返したことの否認不可）や **キャッシュの安全性**（RS が introspection 結果をキャッシュしても改ざん検知ができる）の文脈でも価値がある。

**FAPI 2.0 で重要になる場面**: アクセストークンが JWT として配布される（self-contained token）構成では、RS は JWKS で署名検証すれば introspection を経由せずに済むため、この option の必要性は低い。**reference token（不透明トークン）方式** を採用しているか、**リアルタイム失効反映** のために RS が常に introspection を叩く設計の場合に重要になる。詳細は [付録: Signed Introspection Responses](#signed-introspection-responsesrfc-9701) を参照。

##### conformance testing option とは

「conformance option」「conformance testing option」という用語が登場するのは、**OpenID Foundation の Conformance Testing 制度** の枠組みに由来する。Conformance Testing は実装が仕様の各要件を満たすことを第三者的に検証する仕組みで、認定取得には所定のテストスイートをパスする必要がある。

Message Signing のように複数の独立した機能を含む仕様では、「全部実装した実装」だけを認定対象にすると、現実の部分実装（たとえば signed authorization responses は実装したが signed introspection responses は実装していない、など）を扱えなくなる。そこで、各機能を **独立した conformance option** として定義し、認定を申請する側（**製品ベンダー**＝Keycloak / Auth0 / Authlete のような AS・RP 製品の開発元、あるいは **自社実装する事業者**＝独自に AS・RP を実装する金融機関など）が「我々はこの option について認定を取りたい」と申請できる構造になっている。

Message Signing の場合、3 つの option（signed authorization requests / signed authorization responses / signed introspection responses）はそれぞれ独立した conformance テストが用意されており、認可サーバー（AS）の実装者は「signed responses option のみ実装した」という形で認定を申請できる。仕様文書内の SHALL 句もこの option 単位で適用される（「signed authorization responses option を実装するなら JARM を提供しなければならない」という形）。

なお、本リポジトリのように **既製品（Keycloak）を採用してシステムを構築する立場** や、**PoC・社内検証目的** では、自分で conformance test を回す必要はない。既製品ベンダーが認定取得済みかを確認するのが主な関わり方になる。詳細は「[『FAPI 2.0 対応』と言えるか](#fapi-20-対応と言えるか)」セクションで整理する。

> **Security Profile と Message Signing の関係**
> Security Profile は単独で完結したプロファイルであり、JARM や JAR は要求されない。FAPI 2.0 Security Profile §5.5 は「`response_type=code` のみに限定したことで認可レスポンスは認可コードのみとなり、integrity 保護は obsolete である（不要になった）」と明記している。Message Signing は Security Profile に上記 3 つの conformance option を選択的に追加するための追加プロファイルである。実装は「Security Profile のみ」「Security Profile + signed requests のみ」「Security Profile + signed requests + signed responses」など、目的に応じた組み合わせを選べる。なお sender-constrained token（DPoP/mTLS）は Security Profile の時点ですでに必須であり、Message Signing 固有の要件ではない。

#### FAPI 2.0 Security Profileと Message Signing を組み合わせた場合の処理

ここまで PKCE・PAR・JAR・JARM・DPoP をそれぞれ個別に見てきた。**以降のフルフローは Security Profile に Message Signing の signed authorization requests（JAR）と signed authorization responses（JARM）の両 option を加えた「最大構成」を示す**。FAPI 2.0 Security Profile 単独では JARM は要求されない（PAR + PKCE + 認可レスポンスを `code` のみに限定したことで integrity 保護が obsolete になっているため）が、決済・銀行 API のような高セキュリティ要件の実装では Message Signing の各 option を追加採用する例が多いため、ここでは説明上もっとも要素が揃った状態を扱う。

それぞれの技術要素は互いの弱点を補い合っており、組み合わせることで「金融グレード」と呼べるセキュリティレベルに到達するという考え方である。

フルフローは以下の4フェーズで構成される。

| フェーズ | 技術要素 | 概要 |
| --- | --- | --- |
| 1. 認可リクエスト | PAR + JAR + PKCE | パラメータをサーバー間で送信し、内容を署名で保護する |
| 2. 認可レスポンス | JARM | 認可コードを署名付き JWT で返す |
| 3. トークンリクエスト | PKCE + DPoP | code_verifier を検証し、トークンをクライアント鍵に紐付ける |
| 4. リソースアクセス | DPoP | リクエストのたびに秘密鍵の所持を証明する |

では、これらの技術要素が実際のフローのなかでどのように連携するか、シーケンス図で確認しよう。フロー全体を通じて**クライアントは一切素のパラメータをブラウザ経由で渡さず、すべてサーバー間通信か署名済みオブジェクトで保護している**点に注目してほしい。

```mermaid
sequenceDiagram
    participant RO as リソースオーナー<br>（例：利用者）
    participant B as ブラウザ<br>（User-Agent）
    participant C as RP（クライアント）<br>（例：BFF/Backend）
    participant AS as 認可サーバー<br>（例：Keycloak）
    participant RS as リソースサーバー<br>（例：銀行 API）

    RO->>C: リソースへのアクセスを要求

    note over RO,RS: ── フェーズ 1: 認可リクエスト（PAR + JAR + PKCE） ──

    note over C: 【PKCE】code_verifier を生成
    note over C: 【PKCE】code_challenge = BASE64URL(SHA256(code_verifier))
    note over C: 【JAR】認可パラメータを JWT として秘密鍵で署名<br>（client_id, redirect_uri, scope, state,<br>code_challenge, response_mode=jwt を含む）

    C->>AS: POST /par（クライアント認証: private_key_jwt）
    note over C,AS: 【PAR + JAR】request=＜署名済み JWT＞

    note over AS: 【JAR】Request Object の署名を検証<br>【PKCE】code_challenge を保存

    AS-->>C: { request_uri, expires_in }

    C->>B: リダイレクト指示（?client_id=...&request_uri=urn:...）
    B->>AS: GET /authorize?client_id=...&request_uri=urn:...
    AS->>B: ログイン・同意画面
    B->>RO: 表示
    RO->>B: 認証情報を入力・同意
    B->>AS: 認証・同意を送信

    note over RO,RS: ── フェーズ 2: 認可レスポンス（JARM） ──

    note over AS: 【JARM】{ code, state, iss, exp } を JWT として署名
    AS->>B: リダイレクト ?response=＜署名済み JWT＞
    B->>C: response=＜署名済み JWT＞
    note over C: 【JARM】JWT を検証（署名・iss・aud・exp・state）<br>code を取り出す

    note over RO,RS: ── フェーズ 3: トークンリクエスト（PKCE + DPoP） ──

    note over C: 【DPoP】Proof JWT を生成<br>ヘッダーに公開鍵（jwk）を埋め込み<br>htm=POST, htu=/token, iat, jti を設定し秘密鍵で署名

    C->>AS: POST /token（クライアント認証: private_key_jwt）
    note over C,AS: code, code_verifier,<br>DPoP: ＜Proof JWT（公開鍵入り）＞

    note over AS: 【PKCE】SHA256(code_verifier) == 保存済み code_challenge を検証<br>【DPoP】Proof JWT を検証し公開鍵の JWK Thumbprint を計算<br>access_token の cnf.jkt に埋め込む

    AS-->>C: access_token（cnf.jkt = 公開鍵のフィンガープリント）

    note over RO,RS: ── フェーズ 4: リソースアクセス（DPoP） ──

    note over C: 【DPoP】Proof JWT を再生成<br>htm=GET, htu=/resource, ath=access_token のハッシュ

    C->>RS: GET /resource<br>Authorization: DPoP ＜access_token＞<br>DPoP: ＜Proof JWT（公開鍵入り）＞

    note over RS: access_token 検証（署名・有効期限・スコープ）<br>【DPoP】Proof JWT の公開鍵から JWK Thumbprint を計算<br>access_token の cnf.jkt と一致するか確認<br>Proof JWT の署名を公開鍵で検証<br>ath がトークンのハッシュと一致するか確認

    RS-->>C: 保護されたリソース
    C-->>RO: リソースを表示
```

このフローを見ると、ブラウザ（フロントチャネル）を通過するのは `request_uri`（PAR の参照 URL）と `response`（JARM の署名済み JWT）だけであることがわかる。認可パラメータの実体はサーバー間通信（バックチャネル）で送り済みであり、ブラウザ経由で盗聴・改ざんできる情報はほとんど残っていない。

また、アクセストークンは `cnf.jkt`（クライアント公開鍵のフィンガープリント）を持っており、API へのリクエストごとに対応する秘密鍵で Proof JWT を生成しなければ受け付けられない。仮にトークンが漏洩しても、秘密鍵を持たない第三者は使用できない。

#### 実装チェックリスト

以下に、このフローを実際のシステムで実現するための設定・実装ポイントをまとめる。クライアント（RP）側の実装、認可サーバー（AS = Keycloak）の設定、リソースサーバー（RS = Kong Gateway）の設定の3つに分けて確認しよう。なお RP の実体は BFF/Backend アプリケーション、または Kong を RP モードで動かす場合の Kong Gateway 自身を指す（[FAPI 2.0 における RP の配置パターン](#fapi-20-における-rp-の配置パターン) を参照）。

##### クライアント（RP）

| 項目 | 内容 |
| --- | --- |
| 鍵ペアの管理 | PS256 または ES256 の鍵ペアを生成・保管する |
| private_key_jwt | クライアント認証用 JWT を秘密鍵で署名して /par・/token に送る |
| JAR 生成 | 認可パラメータをまとめた Request Object JWT を秘密鍵で署名する |
| PAR リクエスト | JAR を request パラメータに乗せて /par へ POST する |
| PKCE | code_verifier を生成し、code_challenge（S256）を JAR 内に含める |
| JARM 検証 | 認可レスポンスの JWT を AS の公開鍵で検証し iss・aud（= client_id）・exp・state を確認する |
| DPoP Proof 生成 | リクエストごとに htm・htu・iat・jti を設定した Proof JWT を生成する |
| DPoP ath クレーム | トークンリクエスト後の API 呼び出しでは access_token の SHA-256 ハッシュを ath に含める |

##### 認可サーバー（Keycloak）

| 項目 | 設定箇所 |
| --- | --- |
| PAR 必須化 | Client → Advanced → Pushed authorization request required: ON |
| JAR 検証 | Client → Advanced → Request object signature algorithm: PS256 または ES256 |
| JARM 有効化 | Client → Advanced → Authorization response signature algorithm: PS256 |
| DPoP 有効化 | Client → Advanced → DPoP bound access tokens: ON |
| PKCE 必須化 | Client → Advanced → Proof Key for Code Exchange Code Challenge Method: S256 |
| クライアント認証 | Client → Credentials → Client Authenticator: Signed JWT（private_key_jwt） |
| トークン署名 | Client → Advanced → Access token signature algorithm: PS256 |

##### リソースサーバー（Kong Gateway）

| 項目 | 内容 |
| --- | --- |
| JWT 検証 | `openid-connect` プラグインで AS の JWKS を用いて access_token の署名を検証する |
| DPoP 検証 | `proof_of_possession_dpop: strict` を設定し cnf.jkt と Proof JWT の照合を有効化する |
| スコープ検証 | `scopes_required` に必要なスコープを指定する |

### FAPI 2.0 の対応状況

FAPI 2.0 Security Profile の最終仕様が 2025年2月に承認されたことで、主要 IdP の対応が本格化しつつある。以下に代表的な IdP の対応状況をまとめる。

> **OpenID Foundation の認定は「製品一般」ではなく「組織 × 実装（デプロイメント）」単位で付与される。**[公式 Implementations 一覧](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/) は `Organization | Implementation | Profile列 | 認定日` という構造になっており、エントリごとに「どの組織が、どの製品 / どのデプロイメントで、どの conformance option を取得したか」を示している。Organization 欄には **製品ベンダー自身**（Authlete, Inc / Filip Skokan＝node-oidc-provider 開発者 等）が並ぶケースと、**自社用 IdP を構築した事業者**（例：銀行が自社の `BCP CAS V6` で取得）が並ぶケースの両方が混在する。
>
> したがって以下の比較表で **「OpenID 認定」列が示すのは「その IdP 製品（または製品系統）に紐づく認定エントリが公式一覧に存在するか」** であり、これはあくまで製品選定時の参考指標である。**ある IdP 製品の認定取得は、その製品を採用した個別企業のデプロイメントを自動的に認定するものではない**（採用後にカスタマイズや独自実装で機能を補完していれば、エコシステム認定が必要なら別途自社デプロイメントで認定を取り直す必要がある）。

#### 機能対応・認証取得状況

| IdP | Security Profile | Message Signing | PAR | JAR | JARM | DPoP | OpenID 認定（製品系統に紐づくエントリの有無） |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Keycloak** | ✅（v26.4で公式サポート表明） | ✅（v26.4で公式サポート表明） | ✅ | ✅ | ✅ | ✅（v26.1+） | 適合性テスト通過（公式 Implementations 一覧への掲載は別途確認） |
| **Auth0** | ✅（Enterprise + HRI 必須） | ❌（JARM 未確認） | ✅ | ✅ | 未確認 | 未確認 | Final 仕様での該当エントリ未確認 |
| **Okta** | ⚠️ 根拠不足 | 要確認 | ✅ | 要確認 | 要確認 | ✅ | Final 仕様での該当エントリ未確認 |
| **Microsoft Entra ID** | ❌ | ❌ | ❌ | ❌ | ❌ | 未確認（RFC 9449 準拠の対応を確認できず） | 該当エントリなし |
| **Kong Identity** | 不明 | 不明 | 不明 | 不明 | 不明 | 不明 | 該当エントリ未確認 |

#### 各 IdP の補足

**Keycloak**
FAPI 2.0 への対応が最も進んでいる OSS IdP である。FAPI 2.0 用のクライアントプロファイル（`fapi-2-security-profile` / `fapi-2-dpop-security-profile` / `fapi-2-message-signing`）が組み込まれている。DPoP は v26.1 で導入。Security Profile・Message Signing Final への公式サポート表明は v26.4 のリリースノートによる（v26.1 時点では DPoP 追加のみで、Final 仕様全体のサポート表明ではない）。適合性テストは通過しているが、OpenID Foundation の公式認定一覧（<https://openid.net/certification/>）への掲載状況は別途確認が必要である。

**Auth0**（Okta Customer Identity Cloud）
公式ドキュメント（[Configure FAPI Compliance](https://auth0.com/docs/get-started/applications/configure-fapi-compliance)）によると、`compliance_level` を `fapi2_sp_pkj_mtls`（Private Key JWT + mTLS）または `fapi2_sp_mtls_mtls`（mTLS + mTLS）に設定することで FAPI 2.0 Security Profile に対応できる。PAR は必須、JAR は PS256 署名で対応している。ただし **Enterprise Plan + Highly Regulated Identity アドオンが必要**であり、デフォルトでは無効だ。JARM・DPoP についてはドキュメントに記載がなく未確認。Message Signing の各 conformance option（signed authorization requests / signed authorization responses / signed introspection responses）への対応は確認できていない。OpenID Foundation の公式認定は未取得であるため、第三者が検証した準拠保証はない。

**Okta**（Workforce Identity Cloud）
DPoP と PAR は公式ドキュメントで確認できる。一方 JAR・JARM については確認できておらず、FAPI 2.0 Security Profile 全体への準拠については根拠不足の状態である。表の「⚠️ 根拠不足」は Security Profile 準拠の明示的な根拠（FAPI 2.0 モードへの設定方法の公式説明等）が不足しているという意味であり、PAR・DPoP 機能の有無とは別の判断である。

**Microsoft Entra ID**
PKCE や `private_key_jwt` などの基本的な OAuth 2.0 / OIDC 機能は対応しているが、PAR は認可サーバーとして対応していない。DPoP については Microsoft が PoP（Proof of Possession）トークンの実装を提供しているが、これが RFC 9449 DPoP と同一であるかは本稿執筆時点で確認できていない。「未確認」と「未対応」は区別する必要があるが、**PAR の未対応**が確認できている時点で Security Profile の必須要件を満たせず、FAPI 2.0 準拠の認可サーバーとして使うことができない。なお MSAL はクライアント側ライブラリであり、Entra ID（認可サーバー）の機能とは別物である。

**Kong Identity**
Konnect プラットフォームに組み込まれた OAuth 2.0 / OIDC 認可サーバーである（[ドキュメント](https://developer.konghq.com/kong-identity/)）。クライアントクレデンシャルフローによる M2M 認証に主眼を置いており、Kong Gateway との統合（openid-connect プラグイン・Introspection プラグイン等）が特徴となっている。ただし、PAR・JAR・JARM・DPoP・private_key_jwt といった FAPI 2.0 固有の機能については公開ドキュメントに記述がなく、対応状況は不明である。FAPI 2.0 準拠が要件となる場合は Kong に直接確認することを推奨する。

> 参考：OpenID Foundation は 2023年5月に最初の FAPI 2.0 self-certifications を公開し、Authlete・Cloudentity・ConnectID・Ping Identity・Raidiam 等を掲載した。ただしこれは Implementer's Draft ベースの認定であり、2025年2月承認の Final specification ベースの認定とは区別する必要がある。大手クラウド IdP（Auth0・Okta・Entra ID）の Final spec ベースの認定取得は 2025年時点では確認できない状況である。

## FAPI の沿革

### FAPI 1.0 リリースまで

| 年月 | 出来事 |
| --- | --- |
| 2017年1月 | EU PSD2（決済サービス指令2）施行準備・英国 CMA による Open Banking 義務化を背景に仕様策定の機運が高まる |
| 2017年3月 | OpenID Foundation にて FAPI Working Group 設立（初回会合：2017年3月29日） |
| 2017年2月 | Implementer's Draft 1 Part 1 公開 |
| 2017年7月 | Implementer's Draft 1 Part 2 公開 |
| 2018年10月 | Implementer's Draft 2 承認（JARM を追加） |
| 2019年4月 | 適合性テスト（Conformance Testing）開始 |
| **2021年3月12日** | **FAPI 1.0 Baseline / Advanced 最終仕様（Final Specification）承認** |

### FAPI 2.0 リリースまで

FAPI 1.0 の普及に伴い、実装経験から得られた知見・OAuth 2.0 セキュリティ BCP の進化・より広いユースケースへの対応を目的として FAPI 2.0 の策定が開始された。

| 年月 | 出来事 |
| --- | --- |
| 2021年7月 | FAPI 2.0 Implementer's Draft 1 承認 |
| 2022年11月〜2023年1月 | Implementer's Draft 2 パブリックレビューおよび承認 |
| **2025年2月19日** | **FAPI 2.0 Security Profile / Attacker Model 最終仕様承認** |
| **2025年9月25日** | **FAPI 2.0 Message Signing 最終仕様承認** |

### FAPI 1.0と2.0の相違点

FAPI 1.0 最終仕様（2021年3月）では「Baseline」「Advanced」の2プロファイル構成であったが、FAPI 2.0 では以下の2プロファイルに再編された。

| プロファイル | 参考：FAPI 1.0 の対応概念 | 概要 |
| --- | --- | --- |
| FAPI 2.0 Security Profile | FAPI 1.0 Advanced に相当（さらに強化） | 認可コードフロー + PKCE + PAR + sender-constrained token |
| FAPI 2.0 Message Signing | FAPI 1.0 に独立した Message Signing プロファイルはないが、Advanced では JARM または `code id_token` による認可レスポンス保護があった | Security Profile に対して 3 つの独立した conformance option（signed authorization requests / signed authorization responses / signed introspection responses）を選択的に追加するプロファイル |

FAPI 1.0 からの主な変更点は以下のとおりである。

| 項目 | FAPI 1.0 | FAPI 2.0 |
| --- | --- | --- |
| PKCE | 任意 | **必須**（S256 のみ） |
| PAR（Pushed Authorization Requests） | 任意 | **必須** |
| response_type | `code` / `code id_token`（ハイブリッド） | `code` のみ |
| Implicit Flow | 使用可 | **禁止** |
| クライアント認証 | `client_secret_basic` 等 | `private_key_jwt` または mTLS |
| JWT 署名アルゴリズム | RS256 可 | **PS256 / ES256 / EdDSA のみ** |
| DPoP / mTLS（sender-constrained token） | 対象外 | **Security Profile で必須**（AS は sender-constrained token しか発行不可） |
| JARM（JWT Secured Authorization Response Mode） | FAPI 1.0 Advanced で任意 | Security Profile では不要（PAR + PKCE で integrity 保護は obsolete）。Message Signing の signed authorization responses option を選択した場合のみ必須 |

## 付録 - 用語解説
### RS256/ES256/PS256/S256/RSA-PSS/楕円曲線署名

これらは JWT の署名や PKCE のコード検証に使われるアルゴリズムの識別子である。名前が似ているが、目的・仕組み・強度がそれぞれ異なる。

#### 署名アルゴリズム（JWT の `alg` クレームで指定）

| 識別子 | ベース技術 | 概要 |
| --- | --- | --- |
| **RS256** | RSA + SHA-256 | RSA 秘密鍵で署名し、公開鍵で検証する。実績は豊富だが、鍵サイズが大きく（2048bit 以上推奨）、署名処理が重い |
| **PS256** | RSA-PSS + SHA-256 | RS256 と同じ RSA 鍵を使うが、署名方式を PKCS#1 v1.5 から **PSS（Probabilistic Signature Scheme）** に変更したもの。RS256 より理論的に強固で、FAPI 2.0 では RS256 の代わりにこちらを要求する |
| **ES256** | ECDSA + P-256 + SHA-256 | **楕円曲線**（Elliptic Curve）を使った署名。RSA 系より鍵が短く（256bit）、処理も軽い。モバイル・組み込みに向いており、FAPI 2.0 では PS256 と並んで許可されている |

> **RS256 が FAPI 2.0 で禁止された理由**
> FAPI 2.0 Security Profile は JWT 処理に PS256・ES256・EdDSA のみを要求し、RS256 を許可しない。RS256 が使う PKCS#1 v1.5 パディングは PSS より理論的に弱いとされており、OAuth / JOSE コミュニティの近年のベストプラクティスはより限定されたアルゴリズム集合（PSS 方式・楕円曲線系）の採用に向かっている。これに沿った形で FAPI 2.0 は RS256 を排除している。

#### RSA-PSS とは

RSA-PSS（Probabilistic Signature Scheme）は RSA 署名のパディング方式の一種である。RS256 が使う PKCS#1 v1.5 では署名が決定論的（同じ入力から常に同じ署名が生成される）であるのに対し、PSS はランダムなソルトを混ぜるため署名のたびに異なる値が生成される。PS256 はこの RSA-PSS を SHA-256 と組み合わせたものである。

#### 楕円曲線署名（ECDSA）とは

RSA が「大きな数の素因数分解の困難さ」を安全性の根拠とするのに対し、楕円曲線暗号（ECC）は「楕円曲線上の離散対数問題の困難さ」を根拠とする。同等のセキュリティ強度を RSA の 1/10 以下の鍵長で実現できる。ES256 は P-256 という曲線を使った ECDSA 署名である。

#### S256（PKCE のコード検証方式）

S256 は署名アルゴリズムではなく、**PKCE のコードチャレンジ生成方式**である。

```text
code_verifier（ランダム文字列）
  → SHA-256 ハッシュ
  → Base64URL エンコード
  = code_challenge
```

認可リクエスト時に `code_challenge` を送り、トークンリクエスト時に `code_verifier` を送ることで、認可コードを横取りされても `code_verifier` がなければトークンを取得できないことを保証する。FAPI 2.0 では平文をそのまま送る `plain` 方式を禁止し、S256 のみを許可している。

#### まとめ

| 識別子 | 用途 | 分類 |
| --- | --- | --- |
| RS256 | JWT 署名（FAPI 2.0 では使用不可） | RSA 系 |
| PS256 | JWT 署名（FAPI 2.0 推奨） | RSA 系（PSS） |
| ES256 | JWT 署名（FAPI 2.0 推奨） | 楕円曲線系 |
| S256 | PKCE のコードチャレンジ生成 | ハッシュ（SHA-256） |

### PKCE（Proof Key for Code Exchange）

[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) で定義されている。認可コードフローにおいて、認可コードを横取りされてもアクセストークンを取得できないようにする仕組みである。

#### 何が問題だったか

認可コードフローでは、認可サーバーからブラウザ経由でクライアントに認可コードが渡される。この時点でコードは URL に含まれるため、悪意あるアプリやブラウザ拡張がコードを横取りし、トークンエンドポイントに先に送りつけることができた（Authorization Code Interception Attack）。

#### どうやって解決したか

認可リクエスト時に `code_challenge`（ハッシュ値）だけを送り、`code_verifier`（元の値）はトークンリクエスト時まで手元に秘匿しておく。認可サーバーはトークンを発行する前に「`code_verifier` を SHA-256 したものが、事前に受け取った `code_challenge` と一致するか」を検証する。

攻撃者が認可コードを横取りしても、`code_verifier` はクライアントの手元にしか存在しないため、トークンエンドポイントに code_verifier を正しく提示できず、トークンを取得できない。

#### PKCEの仕組み

```mermaid
sequenceDiagram
    participant RO as リソースオーナー<br>（例：利用者）
    participant B as ブラウザ<br>（例：Chrome、Safari）
    participant C as クライアント<br>（例：スマートフォンアプリ）
    participant AS as 認可サーバー<br>（例：Keycloak）
    participant RS as リソースサーバー<br>（例：銀行 API）

    RO->>C: ① リソースへのアクセスを要求

    note over C: 【PKCE】code_verifier を生成（43〜128文字のランダム値）
    note over C: 【PKCE】code_challenge = BASE64URL(SHA256(code_verifier))

    C->>B: ② 認可エンドポイントへリダイレクト指示
    note over B: client_id, redirect_uri, scope,<br>response_type=code, state,<br>code_challenge, code_challenge_method=S256

    B->>AS: ③ 認可リクエスト送信（GET /authorize?...）
    note over AS: 【PKCE】code_challenge を保存

    AS->>B: ④ ログイン・同意画面を返す
    B->>RO: ログイン・同意画面を表示
    RO->>B: ⑤ 認証情報を入力・同意
    B->>AS: 認証・同意を送信

    AS->>B: ⑥ 認可コードをリダイレクトで返す
    B->>C: ⑦ 認可コードを渡す（リダイレクト URI 経由）

    note over C,AS: ⑧ 以降はブラウザを介さない直接通信（バックチャネル）
    C->>AS: ⑧ トークンリクエスト
    note over C: 【PKCE】code_verifier を初めて送信（code と一緒に）
    note over AS: 【PKCE】SHA256(code_verifier) == 保存済み code_challenge を検証

    AS->>C: ⑨ access_token を発行

    C->>RS: ⑩ API リクエスト（Bearer access_token）
    note over RS: access_token を検証<br>（署名・有効期限・スコープ）
    RS->>C: ⑪ 保護されたリソースを返却
    C->>RO: ⑫ リソースを表示
```

#### S256 が必須な理由

PKCE には `plain`（code_verifier をそのまま送る）と `S256`（SHA-256 でハッシュ）の2方式がある。`plain` では攻撃者が code_challenge を盗んだ時点で code_verifier も判明してしまうため、FAPI 2.0 では `S256` のみを許可している。

#### code_challenge の保存期間

RFC 7636 では `code_challenge` の保存期間は明示されていない。`code_challenge` は認可コードとセットで管理されるため、実質的には**認可コードの有効期限に準じる**。

認可コードの有効期限は OAuth 2.0 の基盤仕様 RFC 6749 に定められており、**最大 10 分を推奨**している。認可コードが使用されるか期限切れになった時点で、紐付く `code_challenge` も合わせて削除される。

> Keycloak のデフォルトは **30 秒**（Admin Console → Realm Settings → Tokens → Authorization Code Lifespan）。

### PAR（Pushed Authorization Requests）

[RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) で定義されている。通常の認可コードフローでは認可パラメータをブラウザのリダイレクト URL に含めるが、PAR ではクライアントが事前にパラメータをサーバー間通信で認可サーバーに「プッシュ」し、代わりに短命の `request_uri` を受け取る。ブラウザには `request_uri` だけを渡すため、パラメータが URL に露出しない。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant AS as 認可サーバー
    participant U as ユーザー（ブラウザ）

    note over C: 認可パラメータを準備
    note over C: client_id, redirect_uri, scope,<br>response_type=code, state,<br>code_challenge, code_challenge_method=S256

    C->>AS: POST /par（クライアント認証付き）
    note over C,AS: ↑ ブラウザを介さないサーバー間通信<br>認可パラメータを全てここで送信

    AS-->>C: { request_uri: "urn:ietf:params:oauth:request_uri:xxx", expires_in: 60 }

    note over C,U: ブラウザには request_uri だけを渡す（パラメータは不露出）
    C->>U: リダイレクト ?client_id=...&request_uri=urn:ietf:params:oauth:request_uri:xxx

    U->>AS: GET /authorize?client_id=...&request_uri=urn:...
    AS->>U: ログイン画面
    U->>AS: 認証・同意
    AS-->>U: リダイレクト ?code=...
    U->>C: code
    C->>AS: POST /token（code + code_verifier）
    AS-->>C: access_token
```

---

### JAR（JWT Secured Authorization Requests）

[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101) で定義されている。認可リクエストのパラメータ全体を署名付き JWT（Request Object）としてまとめ、改ざんを防ぐ仕組みである。FAPI 2.0 Message Signing では PAR と組み合わせて使用し、クライアントが署名した Request Object を PAR エンドポイントへプッシュする。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant AS as 認可サーバー
    participant U as ユーザー（ブラウザ）

    note over C: 認可パラメータを JWT として署名<br/>（client_id, redirect_uri, scope,<br/>code_challenge 等を含む）

    C->>AS: POST /par<br/>request=＜署名済み JWT＞ + クライアント認証
    note over AS: JWT 署名を検証
    AS-->>C: { request_uri }

    C->>U: リダイレクト ?client_id=...&request_uri=urn:...
    U->>AS: GET /authorize
    AS->>U: ログイン画面
    U->>AS: 認証・同意
    AS-->>U: code
    U->>C: code
```

**PAR のみとの違い:** PAR だけではパラメータの到達は保護されるが、送信者（クライアント）の正当性は別途クライアント認証で担保する。JAR を加えることでリクエスト内容自体に署名が入り、リクエストの完全性と送信者性の強化に寄与する。Message Signing 全体として non-repudiation のユースケースを支える要素の一つとなる。

---

### JARM（JWT Secured Authorization Response Mode）

[OpenID Foundation 仕様](https://openid.net/specs/oauth-v2-jarm-final.html) で定義されている。認可レスポンス（認可コード等）を認可サーバーが署名した JWT として返す仕組みである。通常のレスポンスはコールバック URL に `code=xxx&state=yyy` を平文で含むが、JARM では JWT 内に格納されるため、レスポンスの改ざんや Mix-Up 攻撃（別の AS のレスポンスをすり替える攻撃）を防ぐことができる。

なお JARM は **FAPI 2.0 Security Profile では要求されない**。`response_type=code` のみに限定し、認可レスポンスを認可コードだけに絞ったことで、JARM が守ろうとしていた integrity 保護自体が不要になった、というのが Security Profile §5.5 の整理である。FAPI 2.0 で JARM を採用するのは Message Signing の signed authorization responses option を選択したときに限られる。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant AS as 認可サーバー
    participant U as ユーザー（ブラウザ）

    C->>U: リダイレクト（response_mode=jwt を指定）
    U->>AS: GET /authorize?response_mode=jwt&...
    AS->>U: ログイン画面
    U->>AS: 認証・同意

    note over AS: { code, state, iss, exp } を JWT として署名

    AS-->>U: リダイレクト ?response=＜署名済み JWT＞
    U->>C: response=＜署名済み JWT＞

    note over C: JWT を検証<br/>・AS の署名を確認<br/>・iss（発行者）が正しいか確認<br/>・aud（= client_id）が自分宛か確認<br/>・exp（有効期限）を確認<br/>・state が一致するか確認

    C->>AS: POST /token（取り出した code）
    AS-->>C: access_token
```

---

### Signed Introspection Responses（RFC 9701）

[RFC 9701](https://www.rfc-editor.org/rfc/rfc9701)（OAuth 2.0 JWT Secured Introspection Response）で定義されている。Token Introspection（[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)）のレスポンスを通常の JSON ではなく、AS が署名した JWT として返すための拡張である。FAPI 2.0 Message Signing では 3 つの独立した conformance option のひとつとして位置づけられている。

#### 通常の introspection との違い

通常の Token Introspection では、RS（リソースサーバー）が AS の `/introspect` エンドポイントにアクセストークンを送り、AS は以下のような JSON でトークンの状態を返す。

```text
POST /introspect          ┌───────────────┐
─────────────────────────►│  認可サーバー   │
RS                        │     (AS)      │
                          └───────┬───────┘
        application/json          │
        {                         │
          "active": true,         │
          "sub": "alice",         │ ← TLS 終端プロキシや
          "scope": "read",        │   API GW がここに挟まる場合、
          "exp": 1700000000,      │   レスポンス本文を改ざんされる
          "cnf": {                │   余地がある
            "jkt": "..."          │
          }                       │
        }                         │
```

RS はこの JSON をそのまま信用するしかない。TLS による完全性保護はあるが、AS と RS の間に逆プロキシ・WAF・サービスメッシュ等が挟まる場合、TLS は中継ノードで一旦終端される。中継ノードが侵害されると、たとえば `"active": false` を `"active": true` に書き換えたり、`"scope"` を昇格させたりするリプレイ・改ざんが理論上可能になる。

#### Signed Introspection Responses の仕組み

RFC 9701 では、RS が `Accept: application/token-introspection+jwt` ヘッダーを送ることで、AS は以下のような JWT を返す。

```text
POST /introspect
Accept: application/token-introspection+jwt
─────────────────────────────────────────────►
RS                          AS

  application/token-introspection+jwt
  ＜JWT＞

  ヘッダー: { "typ":"token-introspection+jwt", "alg":"PS256", "kid":"..." }
  ペイロード: {
    "iss": "https://as.example.com",      ← AS の発行者識別子
    "aud": "https://rs.example.com",      ← この introspection を要求した RS
    "iat": 1700000000,
    "token_introspection": {
      "active": true,
      "sub": "alice",
      "scope": "read",
      "exp": 1700001000,
      "cnf": { "jkt": "..." }
    }
  }
  署名: AS の秘密鍵による署名
```

RS は AS の公開鍵（JWKS から取得）で署名を検証することで、**中継経路で改ざんされていないことを暗号学的に保証** できる。さらに `iss` と `aud` を検証することで「この introspection 結果は確かにこの AS が、この RS 向けに発行したもの」と確認できる。

#### 何が嬉しいか

| ユースケース | 説明 |
| --- | --- |
| 中継経路の改ざん防止 | TLS 終端プロキシ・WAF・サービスメッシュが挟まる場合、レスポンス本文の整合性を経路に依存せず保証できる |
| 監査・否認不可（non-repudiation） | 「AS が確かにこのトークン情報を返した」ことを後から証明できる。金融系の監査要件や、インシデント調査時の証跡として価値がある |
| キャッシュの安全性 | 署名付きならば RS が introspection 結果をキャッシュしても、改ざん検知ができる（通常の JSON では難しい） |
| ログ転送の安全性 | 監査ログに introspection 結果を記録する際、後から改ざんされていないことを検証できる |

#### FAPI 2.0 における位置づけ

Message Signing 仕様は signed authorization requests（JAR）・signed authorization responses（JARM）と並んで signed introspection responses を独立した conformance option として定義している。実装側はこの option を選択するかどうかを単独で判断でき、選択した場合のみ AS は RFC 9701 を実装する必要がある。

ただし、FAPI 2.0 の標準的な検証フローはアクセストークンが JWT として配布される（self-contained token）構成を想定しており、RS 側で JWKS を使って署名検証すれば introspection を経由せずに検証が完結する。Signed Introspection Responses が実装的に重要になるのは、reference token（不透明トークン）方式を採用している場合や、リアルタイムな失効反映のために RS が常に introspection を叩く設計を取っている場合である。

#### Kong Gateway での対応状況

本リポジトリの Kong = RS 構成では `auth_methods: introspection` を設定しているため、Kong は Keycloak の introspection エンドポイントを叩いてトークンの有効性を確認している。ただし、Keycloak が返すのは通常の JSON であり、`Accept: application/token-introspection+jwt` をリクエストして署名付き JWT を受け取る挙動を `openid-connect` プラグインがサポートしているかは公式リファレンスでの確認が必要である（本稿執筆時点では未検証）。Kong と Keycloak の間に中継ノードが挟まる構成や、強い監査要件がある場合は signed introspection responses の必要性を別途検討すること。

---

### Sender-constrained Access Token と DPoP / mTLS

FAPI 2.0 Security Profile はアクセストークンを **sender-constrained access token** にすることを必須としている。「盗まれたアクセストークンを第三者が使えないようにする」のがゴールで、その実現方式として **DPoP** と **mTLS** の 2 つが認められている。どちらも目的は同じだが、トークンを何にバインドするか・どこで証明するかが違う。

> **`cnf` クレームとは**: [RFC 7800（Proof-of-Possession Key Semantics for JWTs）](https://www.rfc-editor.org/rfc/rfc7800) で定義された JWT 標準クレームで、`cnf` は **"confirmation"**（確認情報）の略。アクセストークンの **正当な使用者を識別するための鍵情報** を埋め込むためのフィールドで、AS がトークンに付与し、RS が API 呼び出し時に「リクエスト元が `cnf` の指す鍵 / 証明書を持っているか」を確認する。サブクレームは方式によって異なり、**DPoP では `cnf.jkt`**（公開鍵の JWK Thumbprint）、**mTLS では `cnf.x5t#S256`**（クライアント証明書の SHA-256 Thumbprint）が使われる。これが入っていることで、トークンが **誰の鍵にバインドされているか** が暗号学的に証明できる仕組みになる。

| 観点 | DPoP（RFC 9449） | mTLS（RFC 8705） |
| --- | --- | --- |
| 紐づけ先 | クライアントの **公開鍵** | クライアントの **証明書** |
| トークン内の `cnf` | `cnf.jkt`（JWK Thumbprint） | `cnf.x5t#S256`（証明書の SHA-256 Thumbprint） |
| API 呼び出し時に必要なもの | リクエストごとに新規生成する DPoP Proof JWT | mTLS 接続でのクライアント証明書 |
| 代表的な HTTP ヘッダー | `Authorization: DPoP <token>` + `DPoP: <proof-jwt>` | `Authorization: Bearer <token>`（証明書は TLS 層で提示） |
| 証明のレイヤー | アプリケーション層（毎リクエスト署名） | TLS 層（接続単位の証明書交換） |

「DPoP用トークン」「mTLS用トークン」と呼ばれることがあるが、より正確には **「DPoP 方式で sender-constrained されたアクセストークン」** / **「mTLS 方式で証明書にバインドされたアクセストークン」** と言うべきである。トークン自体は通常の access_token であり、`cnf` クレームの中身が違うだけで、それぞれ別方式で同じ目的（sender-constraining）を達成している。

#### Kong Gateway がそれぞれの方式で担う役割

| 方式 | クライアント側（RP） | リソースサーバー側（RS） |
| --- | --- | --- |
| **DPoP 方式** | DPoP 鍵ペアを管理し、リクエストごとに DPoP Proof JWT を生成する | `cnf.jkt` と DPoP Proof ヘッダーの公開鍵 thumbprint を照合する |
| **mTLS 方式** | クライアント証明書 + 鍵を管理し、API 呼び出しを mTLS で行う | `cnf.x5t#S256` と TLS 接続で受け取ったクライアント証明書の thumbprint を照合する |

Kong Gateway の `openid-connect` プラグインで現状サポートされている範囲は次の通り（本リポジトリの実証ベース）。

| 機能 | RS としての検証 | RP としての生成 |
| --- | --- | --- |
| DPoP | ✅（`proof_of_possession_dpop: strict`） | ❌ 未対応 |
| mTLS | ✅（`proof_of_possession_mtls: strict` 設定が存在） | ✅（`client_auth: tls_client_auth` で実証済み — 検証 3 を参照） |

つまり Kong は **RS としては DPoP も mTLS も検証できる** が、**RP としてトークンを取りに行く側で使えるのは mTLS のみ**（少なくとも現バージョンの openid-connect プラグインでは）という非対称性がある。検証 2（DPoP 方式の RP）が完成しなかった一方で、検証 3（mTLS 方式の RP）が完成したのは、この非対称性に起因する。

DPoP の詳細は次節（[DPoP（Demonstrating Proof of Possession）](#dpopdemonstrating-proof-of-possession)）、mTLS の詳細はその次（[mTLS Sender-constrained Access Token（RFC 8705）](#mtls-sender-constrained-access-tokenrfc-8705)）で扱う。

---

### DPoP（Demonstrating Proof of Possession）

[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) で定義されている。アクセストークンを発行時にクライアントの公開鍵に紐付けし（sender-constrained token）、トークンが盗まれても別のクライアントが使用できないようにする仕組みである。クライアントはリクエストのたびに秘密鍵で署名した短命の「DPoP Proof JWT」を生成してヘッダーに付与する。リソースサーバーはトークンに埋め込まれた公開鍵と DPoP Proof の署名が一致するかを検証する。

#### 公開鍵の伝達方法

認可サーバーは公開鍵を外部から取得しに行くのではなく、**クライアントが DPoP Proof JWT のヘッダーに公開鍵を直接埋め込んで送る**。認可サーバーはその場でヘッダーから公開鍵を取り出し、署名を検証する。

```text
DPoP Proof JWT の構造

ヘッダー: {
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { <クライアントの公開鍵（JWK 形式）> }  ← 公開鍵がここに入っている
}
ペイロード: {
  "jti": "一意な ID（リプレイ攻撃対策）",
  "htm": "POST",              ← HTTP メソッド
  "htu": "https://as/token",  ← リクエスト先 URL
  "iat": 1234567890           ← 発行時刻（短命であることを保証）
}
署名: 上記を秘密鍵で署名
```

認可サーバーは検証後、公開鍵の **JWK Thumbprint**（公開鍵を正規化して SHA-256 でハッシュした値）をアクセストークンの `cnf.jkt` クレームに埋め込む。

```text
アクセストークン（JWT）の一部:
{
  "sub": "alice",
  "cnf": {
    "jkt": "0ZcOCORZNYy..."  ← 公開鍵のフィンガープリント
  }
}
```

リソースサーバーは API リクエスト受信時に、DPoP Proof の `jwk` から同じく JWK Thumbprint を計算し、`cnf.jkt` と一致するかを確認する。一致すれば「トークンを発行されたクライアントと同じ秘密鍵を持つ者がリクエストしている」ことが証明される。

#### フロー

```mermaid
sequenceDiagram
    participant C as クライアント
    participant AS as 認可サーバー
    participant RS as リソースサーバー

    note over C: 公開鍵・秘密鍵ペアを生成

    note over C: DPoP Proof JWT を生成<br/>ヘッダーに公開鍵（jwk）を埋め込み<br/>ペイロードに htm=POST, htu=/token, iat, jti を設定<br/>秘密鍵で署名
    C->>AS: POST /token<br/>DPoP: ＜Proof JWT（公開鍵入り）＞

    note over AS: ① Proof JWT のヘッダーから公開鍵を取り出す<br/>② 公開鍵で Proof JWT の署名を検証<br/>③ 公開鍵の JWK Thumbprint を計算し<br/>　 access_token の cnf.jkt に埋め込む
    AS-->>C: access_token（cnf.jkt = 公開鍵のフィンガープリント）

    note over C: API 呼び出しごとに DPoP Proof JWT を再生成<br/>ヘッダーに同じ公開鍵（jwk）を埋め込み<br/>ペイロードに htm=GET, htu=/resource,<br/>ath=access_token のハッシュ, iat, jti を設定
    C->>RS: GET /resource<br/>Authorization: DPoP ＜access_token＞<br/>DPoP: ＜Proof JWT（公開鍵入り）＞

    note over RS: ① Proof JWT のヘッダーから公開鍵を取り出す<br/>② 公開鍵の JWK Thumbprint を計算<br/>③ access_token の cnf.jkt と一致するか確認<br/>④ 公開鍵で Proof JWT の署名を検証<br/>⑤ ath がトークンのハッシュと一致するか確認
    RS-->>C: リソース
```

**Bearer トークンとの違い:** Bearer トークンは所持しているだけで利用できる（例：HTTP ヘッダーをコピーするだけで再利用可能）。DPoP トークンは対応する秘密鍵がなければ利用できないため、トークンが傍受・窃取された場合のリスクを大幅に低減できる。

---

### mTLS Sender-constrained Access Token（RFC 8705）

[RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)（OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens）で定義されている。アクセストークンを発行時にクライアントが提示した X.509 証明書に紐付けすることで、トークンが盗まれても **対応するクライアント証明書 + 秘密鍵** を持たない第三者には使えなくなる。FAPI 2.0 Security Profile が要求する sender-constrained token のうち DPoP と並ぶもう一つの方式である。

#### トークンへのバインド方法

クライアントは AS のトークンエンドポイントに **mTLS 接続** で接続する。AS は受け取ったクライアント証明書の **SHA-256 thumbprint** を計算し、発行するアクセストークンの `cnf.x5t#S256` クレームに埋め込む。

```text
アクセストークン（JWT）の一部:
{
  "sub": "alice",
  "cnf": {
    "x5t#S256": "f56NW1NJOnht_aodanu-Rsl180jk8Bt-mK9Er2eiafc"   ← クライアント証明書の SHA-256 thumbprint
  }
}
```

ハッシュは「証明書の DER エンコードを SHA-256 してから base64url（パディングなし）」で計算される（RFC 8705 §3.1）。

#### API 呼び出し時の検証

クライアントは API リクエストを **同じクライアント証明書を提示した mTLS 接続** で行う。リソースサーバー（または前段の API Gateway）は次の二段階で検証する。

1. TLS 終端時に提示されたクライアント証明書を取り出し、SHA-256 thumbprint を計算する
2. アクセストークンの `cnf.x5t#S256` クレームと一致するか比較する

```text
Client -- mTLS(client certificate) --> RS / API Gateway
Authorization: Bearer <access_token>
```

DPoP と違って HTTP のアプリケーション層には **追加のヘッダーが要らない**（証明は TLS 層で完結する）。一方で、Kong / API Gateway / ロードバランサのような中継ノードを通る場合、それぞれの段階で **クライアント証明書の情報を後段に伝達** する仕組み（`X-Client-Cert` ヘッダーなど）が必要になる。Kong の `proof_of_possession_mtls: strict` 設定はこの検証を行うフラグである。

#### DPoP 方式との実装上の違い

| 観点 | DPoP | mTLS |
| --- | --- | --- |
| 鍵の保管 | アプリ内（モバイルアプリのストレージ・サーバーサイドの鍵管理 KMS 等） | 通常 OS / コンテナの証明書ストア・HSM 等 |
| 失効処理 | 鍵の使い回しがなければ実質トークン失効で十分（`jti` 単位） | クライアント証明書の **CRL / OCSP** で失効可能 |
| 既存インフラとの親和性 | 新規実装が必要（OAuth レイヤー） | mTLS は既存企業ネットワークでよく使われる枠組みの延長 |
| 証明書配布 | クライアントが自分で生成可能 | 認証局（CA）からの発行が必要 |

FAPI 2.0 Security Profile はどちらでも準拠と認められる。実装側のエコシステム（モバイルアプリ中心 → DPoP、サーバー間 / 大企業ネットワーク中心 → mTLS）で選ぶケースが多い。

#### mTLS 方式での Kong Gateway の役割

| 役割 | DPoP | mTLS |
| --- | --- | --- |
| **RS としての検証**（受け取った token を確認） | ✅ `proof_of_possession_dpop: strict` | ✅ `proof_of_possession_mtls: strict`（実装あり、本リポジトリでは未実証） |
| **RP としての発行**（自身が token を取得しに行く） | ❌ Kong は DPoP Proof を生成しない | ✅ `client_auth: tls_client_auth` で実証済み（[検証 3](#検証-3-kong--rp--mtls)） |

本リポジトリの検証 3 は「**Kong RP × mTLS 方式の sender-constrained token**」を実際に動かして `cnf.x5t#S256` までトークンに刻まれることを確認している。

## API Gateway の FAPI 2.0 対応状況比較

API Gateway は FAPI 2.0 においてリソースサーバー（RS）として機能し、主に「受け取ったアクセストークンが FAPI 2.0 の要件を満たしているか」を検証する役割を担う。以下は代表的な API Gateway 製品における FAPI 2.0 RS 機能の対応状況である（**公開ドキュメントから確認できた範囲**。「不明」は未調査を意味し、非対応とは異なる）。

> **注意**: この表は API Gateway が **RS として**備える機能の比較であり、IdP（AS）としての機能比較ではない。PAR・JAR・JARM はゲートウェイが OIDC RP / OAuth client mode として動作する場合に関係する機能である。

| 製品 | DPoP 検証 | mTLS 証明書バインド | PAR / JAR / JARM（RP / OAuth client mode 時） | FAPI 明示サポート | 備考 |
| --- | --- | --- | --- | --- | --- |
| **Kong Gateway** | ✅ | ✅ | PAR ✅ / JAR ✅ / **JARM ⚠️ 送信側のみ**（受信側 JWT 検証は未実装、本リポジトリの検証 2 で確認） | ✅ ドキュメントあり | `openid-connect` プラグインで実装。JARM は `response_mode=query.jwt` を AS に送れるが、戻りの JWT を解釈できないため認可フローが完結しない（[検証 2 の補足](#検証-2kong--rpの補足)） |
| **MuleSoft Anypoint** | 不明 | 不明 | 不明 | 不明 | 公開ドキュメントで FAPI 固有 RS 機能を確認できず |
| **AWS API Gateway** | ❌ | ⚠️ トランスポート層のみ | ❌ | ❌ | JWT Authorizer による基本検証のみ。DPoP・証明書バインド検証はカスタム Lambda が必要 |
| **Google Apigee** | 不明 | 不明 | 不明 | 不明 | 公開ドキュメントで FAPI 固有 RS 機能を確認できず。FAPI 準拠が必要な場合は外部 AS やカスタム実装との組み合わせが必要になる可能性がある |
| **IBM API Connect** | 不明 | 不明 | 不明 | 不明 | API Connect 自体の FAPI RS 機能は公開資料から確認できず。IBM Security Verify（ISVA）側には DPoP・cert-bound token 設定があるが、それは AS 側の機能 |

なお、主要なAPI GWとして上記の製品で比較したが、少しマイナーなものも含めると、TykなどではFAPI2.0対応が進んでいる。

### 補足

**AWS API Gateway** は mTLS をトランスポート層でサポートするが、トークンの `cnf` クレームと証明書を照合する「証明書バインド検証」はネイティブ機能としては提供されていない。DPoP 検証も同様で、カスタム Lambda Authorizer での実装が必要になる。なお AWS から証明書バインドトークンを authorizer で照合するサンプル実装が公開されているが、これはネイティブ機能ではなく実装例である。

**Google Apigee** は OAuth トークン管理・検証の一般機能を持つが、DPoP 検証・証明書バインド・FAPI 向け機能は公開ドキュメントから確認できなかった。FAPI 準拠が必要な場合は外部 AS やカスタム実装との組み合わせを検討する必要がある。

**IBM API Connect** 自体の FAPI RS 機能は本稿の調査範囲では確認できなかった。IBM の公開資料では IBM Security Verify（ISVA）側に DPoP バインドトークン・証明書バインドトークンの設定が存在するが、ISVA は AS（認可サーバー）としての機能であり、API Connect（ゲートウェイ）の RS 機能とは別物である。

**Kong Gateway** は FAPI 2.0 の RS 機能（DPoP 検証・mTLS 証明書バインド）をプラグイン 1 つでネイティブにサポートしており、加えて OIDC RP / OAuth client mode として動作する場合の **PAR・JAR は同プラグインで完結** している（本リポジトリの[検証 2](#検証-2-kong--rp) で実証）。他製品と比較して追加実装の必要がない点が特徴である。

ただし **JARM については `response_mode=query.jwt` を AS に送る送信側機能のみが実装されており、AS から戻ってきた JWT 形式の認可レスポンスを検証する受信側機能は未実装** である。設定値としては `query.jwt` を受け付けてしまうが、実際に有効化すると Kong がコールバック URL のクエリ文字列に `code` パラメータを見つけられず、認可フローが先に進まない（詳細は[検証 2 の補足](#検証-2kong--rpの補足)）。**JARM が必要な場合は本稿執筆時点では Kong の openid-connect プラグインだけでは完結しない** ため、Backend / BFF を RP に置く構成が必要になる。

なお FAPI 2.0 Security Profile **本体では JARM は要求されない**（[Message Signing](#fapi-20-message-signing) の signed authorization responses option を採用した場合のみ必須）ため、Security Profile に限った準拠であれば Kong の JARM 受信側未実装は実質的な制約にならない。

---

## Kong Gateway での実装例

### FAPI 2.0 における Kong Gateway の役割

FAPI 2.0 の準拠評価は「システム全体」ではなく **各役割（AS・RP・RS）ごと**に行われる。Kong Gateway は `openid-connect` プラグイン1つで **RS** にも **RP** にもなれる柔軟性を持っており、システムを設計するときに「Kong をどの役割に置くか」がアーキテクチャ上の重要な選択肢になる。本セクションではまず FAPI 2.0 における RP の配置パターンを整理し、Kong が担える2つの役割（RS / RP）のメリット・デメリットを比較する。その上で、本リポジトリで採用している構成（Kong = RS）と、もう一方の構成（Kong = RP）それぞれのフローを具体的に示す。

#### FAPI 2.0 における RP の配置パターン

FAPI 2.0 で最初に決めるべき設計判断の一つが、**RP をどこに置くか** である。RP は AS とのやり取り（PAR/JAR/PKCE/private_key_jwt/DPoP 等）をすべて担う中心的な役割であり、FAPI 2.0 の要件の多くが RP の責務として定義されている。

##### なぜブラウザ／SPA を RP にしないのか

OAuth 2.0 / OIDC の入門書では「SPA がブラウザから直接 AS にトークンを要求する」というパターンがよく登場するが、FAPI 2.0 ではこの構成は推奨されない。理由は以下の3つである。

1. **Confidential Client 要件を満たせない**: FAPI 2.0 は RP のクライアント認証として `private_key_jwt`（クライアント自身の秘密鍵で署名した JWT）または mTLS を要求する。SPA は JavaScript として配信されるため秘密鍵を安全に保持できず、ブラウザのストレージや DOM から鍵が漏洩するリスクを排除できない。
2. **トークンをブラウザに置くリスク**: 高価値 API へのアクセストークンをブラウザに置くと、XSS・ブラウザ拡張・ログ出力・ストレージ管理の不備によってトークンが漏洩する可能性がある。FAPI 2.0 の脅威モデルではこの種の漏洩を許容しない。
3. **DPoP の鍵管理がブラウザに馴染まない**: DPoP はクライアント側で鍵ペアを生成・永続化し、リクエストのたびに署名する仕組みである。ブラウザのストレージ（IndexedDB 等）に依存することになり、永続性・移植性・セキュリティの観点で運用が難しい。

##### 配置パターン比較

| 配置 | RP の主体 | FAPI 2.0 観点 | 適した用途 |
| --- | --- | --- | --- |
| ブラウザ / SPA | JavaScript | ❌ Confidential Client 要件を満たせない、トークン漏洩リスク | 推奨されない |
| Kong Gateway | Kong（OIDC RP モード） | ✅ Confidential Client として動作可能 | PoC・デモ、Backend に OIDC 実装を入れたくない場合、レガシー Backend 統合 |
| Backend / BFF | アプリケーション（サーバーサイド） | ✅ 本番設計として最も自然 | 業務ロジックを持つ Backend がある本番環境 |
| SPA + BFF | BFF（Backend） | ✅ ブラウザにトークンを置かない | SPA フロントエンドを持つ本番アプリ |

ブラウザは「リソースオーナーがログイン画面を操作する User-Agent」として位置づけ、RP は必ずサーバーサイド（Kong / BFF / Backend）に置く、というのが FAPI 2.0 の基本姿勢である。

#### Kong Gateway が担える2つの役割（RS / RP）

Kong Gateway は `openid-connect` プラグインの設定次第で **RS** にも **RP** にもなれる。それぞれの構成のメリット・デメリットを表にまとめる。

| | **Kong = RS（API 保護専用）** | **Kong = RP（OIDC 終端）** |
| --- | --- | --- |
| **Kong の責務** | アクセストークン検証・DPoP / mTLS 検証・スコープ確認 | 上記に加えて、認可コードフロー全体（PAR / JAR 送信、トークン取得、JARM 検証）・セッション管理・logout |
| **メリット** | ・**責務分離が明確** で、Kong は API 保護のみに専念できる<br>・業務ロジック・consent・トークンライフサイクル制御を Backend / BFF 側で **自由に書ける**<br>・セッション・独自 state を Backend で持てるので **拡張性が高い**<br>・Kong プラグインの機能制約に縛られない<br>・Backend ごとに認証・認可ポリシーを差別化しやすい | ・**OIDC RP 機能を Kong に一元化できる**（複数 Backend 横断の認証ポリシー・セッション管理・監査ログが Kong に集約され、ガバナンスが効きやすい。Backend 側で OIDC を再実装する必要もなく一貫性を保てる）<br>・Backend が OAuth / OIDC を **一切意識せずに済む**（OAuth 非対応のレガシー Backend をそのまま FAPI 2.0 配下に置ける）<br>・PAR / JAR / `private_key_jwt` / mTLS の RP 機能が **deck の設定だけで動く**（実装ゼロ）<br>・PoC・検証環境を **短時間で組める**<br>・セッション管理・トークン更新・logout を Kong が肩代わり |
| **デメリット** | ・**Backend / BFF に OIDC RP 実装が必須**（FAPI 2.0 のクライアント側責務をすべて Backend が担う）<br>・Backend を所有・改修できない場合は採用不可<br>・**OIDC 実装が Backend ごとに分散** するため、ポリシー一貫性の担保や監査の集約に運用コストがかかる | ・一元化の裏返しとして **Kong が単一障害点 / ボトルネック** になりやすい（Kong が落ちるとすべての保護下 API が使えなくなる、性能要件は Kong 側でスケール設計が必要）<br>・**Kong プラグインの機能制約に縛られる**（検証 2 で判明：DPoP の RP 側生成不可・JARM の RP 側受信不可など、Backend 側で迂回することもできない。詳細は[検証 2 の補足](#検証-2kong--rpの補足)）<br>・consent 取り消し等の業務固有ロジックを **Backend 側で動かしにくい**<br>・セッションストア・Cookie 設計を Kong 側で持つ必要があり、運用設計が増える |
| **適した場面** | 本番設計、業務ロジックを持つ Backend がある高セキュリティ API、Backend ごとに独自の認可ロジックを持たせたい場合 | PoC・デモ、レガシー Backend 統合、BFF 代替、**複数 Backend を共通の OIDC ポリシーで一括保護したい場合** |

実運用での選び方の指針は以下の通り。

- **本番の金融系・高セキュリティ API** → Backend/BFF を RP、Kong を RS にする構成が最も素直。RP の責務（セッション、トークンライフサイクル、consent、logout、監査）はアプリケーション層に置く方が自然
- **PoC・デモ・FAPI 機能の検証** → Kong を RP にすると `openid-connect` プラグインの設定だけで FAPI 2.0 フローが動かせるため、検証環境を素早く構築できる
- **OAuth 非対応のレガシー Backend を FAPI 2.0 化したい** → Kong を RP にすれば Backend は無改修で FAPI 2.0 の保護下に置ける

#### 本リポジトリの位置づけ

本リポジトリは **Kong = RS** と **Kong = RP** の両構成を提供している。さらに RP 構成については **`private_key_jwt` 版** と **mTLS 版** の2系統を用意し、合計 3 種類の検証パスを切り替えながら動かせる。同じ Keycloak realm（`fapi2`）を共有し、Kong に投入する deck ファイルを差し替えることで順に検証する構成である。同時に動かす想定はない。

| 構成 | deck ファイル | Keycloak クライアント | 検証スクリプト | 主に何を見るか |
| --- | --- | --- | --- | --- |
| **検証 1: Kong = RS** | `deck/rs.yaml` | `fapi2-test-client`（client_secret_post） | `scripts/dpop_e2e_verify.py` | Kong が DPoP-bound アクセストークンを正しく検証して RS として保護できること |
| **検証 2: Kong = RP**（private_key_jwt） | `deck/rp.yaml` | `kong-rp-client`（private_key_jwt + PAR + JAR） | `scripts/rp_e2e_verify.py` | Kong がブラウザ向けに OIDC 認可コードフローを終端し、PAR・JAR・private_key_jwt を実装して RP として動作できること。**ただし sender-constrained token は未到達**（JARM・DPoP は Kong プラグインの制約で不可、詳細は [検証 2（Kong = RP）の補足](#検証-2kong--rpの補足)） |
| **検証 3: Kong = RP × mTLS** | `deck/rp-mtls.yaml` | `kong-rp-mtls-client`（client-x509 + cert-bound tokens） | `scripts/rp_mtls_e2e_verify.py` | Kong が **mTLS クライアント認証** で Keycloak とトークン交換し、`cnf.x5t#S256` を持つ **証明書バインドのアクセストークン** を取得できること。FAPI 2.0 Security Profile が要求する **sender-constrained token を mTLS 経路で実現** する |

それぞれの構成のセットアップ・検証手順は「[検証 1: Kong = RS](#検証-1-kong--rs)」「[検証 2: Kong = RP](#検証-2-kong--rp)」「[検証 3: Kong = RP × mTLS](#検証-3-kong--rp--mtls)」で詳述する。

##### 検証 1（Kong = RS）の補足

検証 1 では curl スクリプト（および Python スクリプト）を「RP」として動作させているが、これは**サーバーサイドで動作する Confidential Client（≒ BFF/Backend RP）を模した簡易検証**である。FAPI 2.0 ではブラウザを RP にしない設計が前提のため、本検証もその前提に従っている。本番構成では curl の位置に BFF/Backend アプリケーション（または検証 2 と同様に別の Kong を RP モードで配置）が入ることになる。

なお、検証 1 はクライアント認証に `client_secret_post` を使っており、FAPI 2.0 が要求する `private_key_jwt` または mTLS には到達していない。PAR/PKCE/DPoP の Kong 受け入れ挙動を確認するための簡易検証である。

##### 検証 2（Kong = RP）の補足

検証 2 では Kong 自身が **FAPI 2.0 Confidential Client** として動作し、**`private_key_jwt`（PS256 署名のクライアント認証）・PAR・JAR（署名済み Request Object）** を Kong プラグイン側で行う。Backend（httpbin）は OAuth/OIDC を一切意識せず、Kong から渡されるユーザー情報ヘッダー（`x-userinfo-*`）を受け取るだけでよい。

###### Kong の openid-connect プラグインの限界（FAPI 2.0 RP として）

検証 2 の構成は完全な FAPI 2.0 RP には到達していない。具体的には以下の機能が Kong RP 側で実現できない／本検証では使用していない。

| 機能 | 状態 | 理由 |
| --- | --- | --- |
| PAR | ✅ 使用 | `require_pushed_authorization_requests: true` でプラグインが対応 |
| JAR（署名済み Request Object） | ✅ 使用 | `require_signed_request_object: true` でプラグインが対応 |
| `private_key_jwt` | ✅ 使用 | `client_auth: private_key_jwt` + `client_jwk` で PS256 署名 |
| PKCE S256 | ✅ 使用 | `require_proof_key_for_code_exchange: true` |
| JARM（署名済み認可レスポンス） | ⚠️ 使用しない | Kong プラグインで `response_mode: query.jwt` を指定すると、Kong がコールバック時の JARM JWT を認識せず認可フローを最初からやり直す挙動となる。検証では JARM を無効化して plain `code` で受信。Keycloak 側の JARM サポート自体は確認済み |
| DPoP（sender-constrained token） | ❌ 使用しない | Kong の openid-connect プラグインは **DPoP の検証（RS 用途）** のみをサポートし、**RP として DPoP Proof JWT を生成する機能はない**。token endpoint への DPoP 提示が必要な構成（Keycloak 側 `dpop.bound.access.tokens=true`）にすると、Kong の token request が `invalid_dpop_proof` で失敗するため、本検証では Keycloak 側の DPoP 要件も外している |

したがって検証 2 で実証されるのは **FAPI 2.0 Security Profile の大部分（PAR + PKCE + private_key_jwt + JAR）** であり、**JARM と DPoP の RP 側機能は未達** である。

ただし FAPI 2.0 が sender-constrained token に求めるのは「**DPoP または mTLS のいずれか**」なので、DPoP の代わりに mTLS で sender-constrained token を実現するパスがある（[検証 3: Kong = RP × mTLS](#検証-3-kong--rp--mtls)）。Kong の openid-connect プラグインは `client_auth: tls_client_auth` をサポートしており、mTLS 経路で `cnf.x5t#S256` を持つ証明書バインドのアクセストークンを取得できる（実証済み）。検証 2 と検証 3 を **DPoP 方式 vs mTLS 方式の対比** として読み比べると、Kong で FAPI 2.0 Security Profile の sender-constrained 要件を満たすルートが見える。

##### 検証 3（Kong = RP × mTLS）の補足

検証 3 では **検証 2 で諦めた sender-constrained token を mTLS 方式で実現** する。Kong は Keycloak の HTTPS+mTLS 専用エンドポイント（`mtls_endpoint_aliases`）に対してクライアント証明書を提示し、Keycloak はその証明書の SHA-256 thumbprint を `cnf.x5t#S256` クレームに埋め込んでアクセストークンを発行する。

| 機能 | 検証 2（private_key_jwt） | 検証 3（mTLS） |
| --- | --- | --- |
| クライアント認証 | `private_key_jwt`（PS256） | `tls_client_auth`（X.509 client cert） |
| sender-constrained token | ❌（DPoP 未対応） | ✅（`cnf.x5t#S256` あり） |
| PAR / PKCE / JAR | ✅ | ✅ / ✅ / 未使用（鍵管理の都合） |
| Backend 連携 | `x-userinfo-*` ヘッダー | 同上 |
| 必要な追加要素 | 鍵ペア（PS256 JWK） | 鍵ペア + 証明書 + CA + Keycloak HTTPS 設定 |

検証 3 は「**Kong の openid-connect プラグインだけで Security Profile の sender-constrained 要件まで到達できる**」ことを示す構成となる。なお JARM はこちらでも未使用（要件は Message Signing 側）。

#### Kong を RS として使う場合のフロー

ここからは Kong = RS 構成（本リポジトリで採用）のフルフローを示す。RP（curl スクリプトが模す Backend/BFF）と AS（Keycloak）が PAR/JAR/PKCE/JARM/DPoP を交わしてトークンを取得し、最終フェーズの API 呼び出しで Kong が DPoP 検証を実施する。**太枠で囲まれた部分が Kong Gateway の担当範囲**である。

```mermaid
sequenceDiagram
    participant RO as リソースオーナー<br>（例：利用者）
    participant B as ブラウザ<br>（User-Agent）
    participant C as RP<br>（例：BFF/Backend）
    participant AS as 認可サーバー<br>（Keycloak）
    participant KG as ≪Kong Gateway≫<br>リソースサーバー（RS）
    participant API as バックエンド API

    RO->>C: リソースへのアクセスを要求

    note over RO,API: ── フェーズ 1: 認可リクエスト（PAR + JAR + PKCE） ── ※Kong は不関与

    note over C: 【PKCE】code_verifier 生成<br>【JAR】認可パラメータを JWT として署名
    C->>AS: POST /par（private_key_jwt 認証）<br>request=＜署名済み JAR＞
    note over AS: JAR 署名検証・code_challenge 保存
    AS-->>C: { request_uri }
    C->>B: リダイレクト（request_uri のみ）
    B->>AS: GET /authorize?client_id=...&request_uri=urn:...
    AS->>B: ログイン・同意画面
    RO->>B: 認証・同意
    B->>AS: 送信

    note over RO,API: ── フェーズ 2: 認可レスポンス（JARM） ── ※Kong は不関与

    note over AS: 【JARM】response JWT を署名
    AS->>B: リダイレクト ?response=＜署名済み JWT＞
    B->>C: response=＜署名済み JWT＞
    note over C: JARM JWT 検証（署名・iss・aud・exp・state）

    note over RO,API: ── フェーズ 3: トークンリクエスト（PKCE + DPoP） ── ※Kong は不関与

    note over C: 【DPoP】Proof JWT 生成（公開鍵埋め込み）
    C->>AS: POST /token（code + code_verifier + DPoP Proof）
    note over AS: code_verifier 検証・DPoP 検証<br>cnf.jkt をトークンに埋め込む
    AS-->>C: access_token（cnf.jkt 付き）

    note over RO,API: ── フェーズ 4: リソースアクセス ── ※ここから Kong Gateway が担当

    note over C: 【DPoP】Proof JWT 再生成（ath = access_token のハッシュ）
    C->>KG: GET /resource<br>Authorization: DPoP ＜access_token＞<br>DPoP: ＜Proof JWT＞

    rect rgb(220, 240, 255)
        note over KG: 【Kong が実施する検証】<br>① access_token の署名・有効期限・スコープ検証<br>　（Keycloak JWKS または introspection を使用）<br>② DPoP Proof の署名を公開鍵で検証<br>③ Proof の公開鍵の JWK Thumbprint を計算<br>④ access_token の cnf.jkt と一致するか確認<br>⑤ ath が access_token のハッシュと一致するか確認<br>⑥ 全検証パス → バックエンドにリクエストを転送
        KG->>API: GET /resource（転送）
        API-->>KG: レスポンス
    end

    KG-->>C: 保護されたリソース
    C-->>RO: リソースを表示
```

#### Kong を RP として使う場合のフロー

次に、Kong を RP として配置する構成を見ていく。この構成では Kong が「ブラウザを終端する OIDC RP」となり、PAR / JAR / PKCE / private_key_jwt / DPoP / JARM などを Kong プラグインが肩代わりする想定である。Backend は OIDC を一切意識せず、Kong から渡されるユーザー情報（ヘッダー経由）だけを見て業務処理を行えばよい。

> **注意**: 以下のシーケンス図と YAML 設定例は **「FAPI 2.0 + Message Signing をすべて RP に取り込んだ最大構成」** を示すための理論モデルである。本リポジトリの[検証 2](#検証-2-kong--rp) で実証したところ、Kong の `openid-connect` プラグインの現バージョンでは **DPoP の RP 側生成と JARM の RP 側受信が未実装** のため、図中の DPoP / JARM 部分は **実際には Kong だけでは完結しない**（詳細は[検証 2 の補足](#検証-2kong--rpの補足)）。完結する範囲（PAR + JAR + private_key_jwt + PKCE）が[検証 2](#検証-2-kong--rp)、sender-constrained を mTLS 経路で実現したのが[検証 3](#検証-3-kong--rp--mtls) である。

OAuth 非対応のレガシー Backend を FAPI 2.0 の保護下に置きたい場合や、PoC として Kong プラグインの設定だけで FAPI 2.0 フローを動かしたい場合に有効な構成である。

##### シーケンス図

太枠で囲まれた部分が Kong Gateway の担当範囲である。RS 構成と比較すると Kong が **すべてのフェーズに関与する** 点が大きく異なる。

```mermaid
sequenceDiagram
    participant RO as リソースオーナー<br>（例：利用者）
    participant B as ブラウザ<br>（User-Agent）
    participant KG as ≪Kong Gateway≫<br>RP モード
    participant AS as 認可サーバー<br>（Keycloak）
    participant API as バックエンド API<br>（OAuth 非対応でも可）

    RO->>B: アプリケーションにアクセス
    B->>KG: GET /protected
    note over KG: セッション Cookie がない<br>→ OIDC フロー開始

    rect rgb(220, 240, 255)
        note over RO,API: ── フェーズ 1: 認可リクエスト（PAR + JAR + PKCE） ──

        note over KG: 【PKCE】code_verifier 生成<br>【PKCE】code_challenge = BASE64URL(SHA256(code_verifier))<br>【JAR】認可パラメータを秘密鍵で JWT 署名<br>　（client_id, redirect_uri, scope, state,<br>　 code_challenge, response_mode=jwt を含む）
        KG->>AS: POST /par（クライアント認証: private_key_jwt）<br>request=＜署名済み JAR＞
        note over AS: 【JAR】Request Object の署名を検証<br>【PKCE】code_challenge を保存
        AS-->>KG: { request_uri, expires_in }
        KG->>B: 302 リダイレクト<br>Location: /authorize?client_id=...&request_uri=urn:...
    end

    B->>AS: GET /authorize?client_id=...&request_uri=urn:...
    AS->>B: ログイン・同意画面
    B->>RO: 表示
    RO->>B: 認証情報を入力・同意
    B->>AS: 認証・同意を送信

    rect rgb(220, 240, 255)
        note over RO,API: ── フェーズ 2: 認可レスポンス（JARM） ──

        note over AS: 【JARM】{ code, state, iss, exp } を JWT として署名
        AS->>B: 302 リダイレクト Kong コールバック<br>Location: /callback?response=＜署名済み JWT＞
        B->>KG: GET /callback?response=＜署名済み JWT＞
        note over KG: 【JARM】JWT を検証<br>（署名・iss・aud・exp・state）<br>code を取り出す

        note over RO,API: ── フェーズ 3: トークンリクエスト（PKCE + DPoP） ──

        note over KG: 【DPoP】Proof JWT を生成<br>ヘッダーに公開鍵（jwk）を埋め込み<br>htm=POST, htu=/token, iat, jti を設定し秘密鍵で署名
        KG->>AS: POST /token（クライアント認証: private_key_jwt）<br>code, code_verifier, DPoP: ＜Proof JWT＞
        note over AS: 【PKCE】SHA256(code_verifier) == 保存済み code_challenge を検証<br>【DPoP】Proof JWT を検証し公開鍵の JWK Thumbprint を計算<br>access_token の cnf.jkt に埋め込む
        AS-->>KG: access_token（cnf.jkt = 公開鍵のフィンガープリント）

        note over KG: ・access_token をセッションに保存<br>・セッション Cookie をブラウザに発行
        KG->>B: 302 リダイレクト 当初の /protected へ<br>Set-Cookie: session=...
    end

    B->>KG: GET /protected（Cookie: session=...）

    rect rgb(220, 240, 255)
        note over RO,API: ── フェーズ 4: バックエンド呼び出し ──

        note over KG: ・セッションから access_token を取り出す<br>・必要に応じて DPoP Proof を再生成<br>　（htm=GET, htu=/protected, ath=access_token のハッシュ）<br>・ユーザー情報をヘッダー（X-Userinfo 等）に埋めて転送
        KG->>API: GET /protected<br>X-Userinfo: ＜ユーザー情報 JWT＞
        API-->>KG: レスポンス
    end

    KG-->>B: レスポンス
    B-->>RO: 表示
```

##### openid-connect プラグインの RP モード設定例

以下は Kong を RP モードで動作させる場合の `deck.yaml` のプラグイン設定例（説明用の抜粋）である。本リポジトリでは [`deck/rp.yaml`](deck/rp.yaml) として実装済みで、`scripts/rp_e2e_verify.py` で検証できる。実際の手順は「[検証 2: Kong = RP](#検証-2-kong--rp)」を参照。

```yaml
plugins:
  - name: openid-connect
    config:
      # ── 基本設定 ──
      issuer: http://keycloak.localhost:9080/realms/fapi2
      client_id:
        - kong-rp-client
      # FAPI 2.0 が要求する強いクライアント認証（共有シークレット禁止）
      client_auth:
        - private_key_jwt
      # private_key_jwt 用の JWK（秘密鍵を含む）
      client_jwk:
        - {"kty":"RSA","kid":"kong-rp-key-1","alg":"PS256","n":"...","e":"AQAB","d":"...","p":"...","q":"...","dp":"...","dq":"...","qi":"..."}
      client_alg:
        - PS256

      # ── 動作モード（RP として認可コードフローを終端）──
      auth_methods:
        - authorization_code   # 未認証時に認可コードフローを起動
        - session              # 認証済みセッションは Cookie で維持
      redirect_uri:
        - https://api.example.com/callback

      # ── PAR を必須化 ──
      pushed_authorization_request_endpoint: http://keycloak:8080/realms/fapi2/protocol/openid-connect/ext/par/request
      require_pushed_authorization_requests: true

      # ── JAR（Request Object 署名）──
      require_signed_request_object: true
      request_object_signing_algorithm: PS256

      # ── JARM（認可レスポンスの署名）──
      response_mode:
        - jwt
      authorization_signed_response_alg: PS256

      # ── PKCE ──
      pkce: strict
      pkce_method: S256

      # ── DPoP（クライアント側で Proof を生成し sender-constrained token を取得）──
      proof_of_possession_dpop: strict
      dpop_proof_lifetime: 60

      # ── スコープ ──
      scopes:
        - openid
        - profile

      # ── セッション管理 ──
      session_storage: cookie
      session_cookie_name: kong_session
      session_cookie_secure: true
      session_cookie_http_only: true
      session_cookie_same_site: Lax
      session_absolute_timeout: 3600

      # ── Backend へのユーザー情報伝達 ──
      upstream_headers_claims:
        - sub
        - preferred_username
        - groups
      upstream_headers_names:
        - X-Userinfo-Sub
        - X-Userinfo-Username
        - X-Userinfo-Groups

      # ── ログアウト ──
      logout_path: /logout
      logout_methods:
        - GET
      logout_revoke: true
      logout_revoke_access_token: true
```

主要な設定キーの意味は以下の通り。

- **`auth_methods: [authorization_code, session]`** — 未認証時に認可コードフロー（RP モード）を起動し、認証済みリクエストは Cookie のセッションで認可する。RS 構成では `introspection` を指定していたが、RP では `authorization_code` を指定する点が決定的に異なる
- **`client_auth: private_key_jwt` + `client_jwk`** — FAPI 2.0 の Confidential Client 要件を満たす。Kong は `client_jwk` の秘密鍵で client assertion JWT を署名し、PAR・トークンエンドポイントへ送る
- **`require_pushed_authorization_requests: true`** — Kong が必ず PAR エンドポイント経由で認可リクエストを送る。素の `/authorize` を直接叩く挙動を禁止する
- **`require_signed_request_object: true` + `request_object_signing_algorithm: PS256`** — PAR リクエストに JAR（署名済み Request Object）を載せる。Message Signing 要件を満たす
- **`response_mode: [jwt]` + `authorization_signed_response_alg: PS256`** — JARM で認可レスポンス（code 等）を署名済み JWT で受け取る設定。**ただし本稿執筆時点の Kong プラグインでは送信側のみ実装で受信側 JWT の検証が未対応**のため、実際に有効化すると認可フローがコールバック時点で停止する（[検証 2 の補足](#検証-2kong--rpの補足) 参照）
- **`pkce: strict` + `pkce_method: S256`** — PKCE を必須化、ハッシュ方式は S256 のみ許可
- **`proof_of_possession_dpop: strict`** — Kong 自身が DPoP Proof を生成し、sender-constrained なアクセストークンを取得する。RS 構成では「受け取った Proof を検証する」だったが、RP では「Proof を生成する」側になる
- **`upstream_headers_claims` / `upstream_headers_names`** — トークンから取り出したクレームをヘッダーで Backend に伝える。Backend は OAuth を意識せず、ヘッダーだけ見ればよい
- **セッション・Cookie 設定** — Kong がセッションを保持するための設定。Cookie 方式はステートレスでスケールしやすいが、Cookie サイズ制限（4KB 程度）がある。可用性が必要なら `session_storage: redis` などサーバーサイドストアを選ぶ

> **注意**: 上記の設定キー名は `openid-connect` プラグインのバージョンによって細部が異なる場合がある。実際に投入する前に [Kong 公式リファレンス](https://developer.konghq.com/plugins/openid-connect/reference/) で対象バージョンの正確なキー名・型を確認すること。

##### 適しているシナリオ

- **OAuth 非対応のレガシー Backend を FAPI 2.0 化したい**: Backend は無改修で、Kong から渡されるユーザー情報ヘッダーだけ見ればよい
- **複数の Backend を統合する集約点**: 認証・認可を Kong に集中させ、各 Backend は業務ロジックに専念
- **PoC・デモ**: Kong プラグインの設定だけで FAPI 2.0 フローが動くため、Backend を作り込まずに検証可能
- **BFF を別途立てるほどではない小規模構成**: Kong を BFF 代わりに使うことで、コンポーネント数を抑える

##### 運用上の注意点

- **セッションストアの可用性**: `session_storage: cookie` はステートレスだが、Cookie サイズ制限と暗号鍵管理が必要。`redis` 等を使う場合は Redis 自体の可用性設計が必要
- **Cookie 属性**: `Secure` `HttpOnly` `SameSite` を適切に設定。CSRF 対策・トークン漏洩防止の最後の砦になる
- **ログアウトの整合性**: Kong 側セッションと Backend 側状態の整合（Backend がセッション情報を持たない設計が望ましい）
- **fine-grained consent**: ユーザー文脈や細粒度な同意管理が必要なら、Backend 側に追加実装が必要になる場合がある
- **複数 DP（Data Plane）構成**: 複数の Kong DP を立てる場合、セッションストアを共有するかスティッキーセッションを設計する必要がある

### openid-connect プラグインの FAPI 対応機能

Kong Gateway の `openid-connect` プラグインは、FAPI 2.0 に必要な技術要素をサポートしている。

| 機能 | プラグイン設定 | 対応する FAPI 要件 | 主な動作モード |
| --- | --- | --- | --- |
| PAR | `pushed_authorization_request_endpoint` | Security Profile: PAR 必須 | RP モード |
| JAR | `require_signed_request_object: true` | Message Signing: JAR | RP モード |
| JARM | `response_mode: query.jwt` 等 | Message Signing: JARM | RP モード（**送信側のみ実装**：受信側の JWT 検証は未対応で、実際に有効化すると認可フローが停止する。詳細は[検証 2 の補足](#検証-2kong--rpの補足)） |
| DPoP 検証 | `proof_of_possession_dpop: strict` | Security Profile: sender-constrained token | RS モード |
| mTLS 証明書バインド検証 | `proof_of_possession_mtls: strict` | Security Profile: sender-constrained token | RS モード |
| mTLS クライアント認証 | `client_auth: tls_client_auth` | Security Profile: 強いクライアント認証 | RS モード |
| スコープ検証 | `scopes_required` | Security Profile: 必要なスコープの強制 | RS モード |

参考: [openid-connect プラグイン FAPI ドキュメント](https://developer.konghq.com/plugins/openid-connect/#financial-grade-api-fapi)

### 「FAPI 2.0 対応」と言えるか

技術的な機能としては FAPI 2.0 に必要な要素をカバーしており、RS として DPoP/mTLS の検証を正しく実施できる点で**「FAPI 2.0 のリソースサーバー要件を技術的に満たせる」**と言える。一方で注意点が2つある。

**役割の分担**: Kong 単体での FAPI 2.0 準拠は成立しない。AS（Keycloak）・クライアント・RS（Kong）の3者がそれぞれの要件を満たして初めてシステム全体が準拠となる。

**正式な適合性認証**: OpenID Foundation は FAPI 2.0 の [Conformance Testing](https://openid.net/certification/) を提供しており、「FAPI 2.0 準拠」を公式に謳うには認定取得が事実上の前提となる。重要なのは **認定が「組織 × 実装（デプロイメント）」単位で付与される** という点で、製品ベンダー（例：Authlete, Inc）が自社製品で認定を取った場合と、エンドユーザー企業（例：銀行）が自社カスタム IdP で認定を取った場合の両方が公式 Implementations 一覧に並ぶ。**製品ベンダーが認定を取得していても、その製品を採用した別企業のデプロイメントが自動的に認定されるわけではない**。Kong Gateway 自体がこの認定を取得しているかどうか、また自社のデプロイメントに認定が必要かどうかは、立場（次節）に応じて判断する。

#### 立場別：conformance test との関わり方

Conformance test を意識する必要がある立場と、そうでない立場を整理する。本リポジトリの読者の多くは「既製品（Kong + Keycloak）を採用してシステムを構築する立場」または「PoC・社内検証目的」に該当するため、自分でテストスイートを回す必要はない。一方で、ベンダー側が認定取得しているかを確認することは設計判断に影響する。

| 立場 | conformance test を意識するか | 関わり方 |
| --- | --- | --- |
| AS / RP / RS の **製品ベンダー**（Keycloak / Auth0 / Authlete 等の開発元） | ✅ 強く意識する | 「FAPI 2.0 準拠」を謳うために自社実装で OpenID Conformance Suite を回し、self-certification として OpenID Foundation に結果を提出する |
| **Open Banking 系エコシステムへの参加企業**（英国 OBIE・ブラジル Open Finance・豪 CDR 等） | ✅ 意識する必要がある | エコシステム参加要件として「FAPI 認定取得済み」が義務化されているケースがある。独自実装する場合は自社実装の認定取得が必要、製品調達する場合は認定取得済みベンダーから選ぶ必要がある |
| 既製品を採用してシステムを構築する **金融機関・SI**（本リポジトリの想定読者の一部） | △ 限定的 | ベンダー側の認定取得状況を確認するのが主な関わり方。「採用する製品系統に認定エントリがあるか（例：Keycloak v26.4 ベースの認定エントリ）」「対象 option（Security Profile / Message Signing の各 option）がカバーされているか」を調達基準に組み込む。**自社のデプロイメントに認定が必要な場合（Open Banking エコシステム参加など）は、認定済み製品をベースにしていても自社デプロイメントで別途認定取得が必要** |
| **PoC・社内検証・学習目的**（本リポジトリの主な目的） | ❌ 不要 | 自分で認定を取る必要はない。仕様の挙動を正しく理解し、必要なときに認定済み実装に切り替えられる構成を設計しておけばよい |

##### 自社実装する場合の流れ（参考）

もし自社で AS / RP / RS を実装する場合、認定取得は以下の流れになる。

1. [OpenID Conformance Suite](https://openid.net/certification/op_servers/) を入手し、自分の実装に対してテストを実行する
2. self-certification の形でテスト結果を OpenID Foundation に提出する
3. 認定リスト（<https://openid.net/certification/>）に掲載される
4. 仕様改訂や Errata に応じて再認定が必要になることがある

ただし FAPI 2.0 で完全自社実装を選ぶ事業者は少数派で、実態としては Authlete・Keycloak・Auth0 HRI などの認定済み実装を採用するケースが大半である。

> Keycloak の FAPI 関連設定（`require.pushed.authorization.requests` 等）は UI のラベル名がバージョンによって異なる場合がある。本リポジトリは Keycloak 26.x を対象としている。

### 検証 1: Kong = RS

Kong Gateway の `openid-connect` プラグインを **RS モード** で設定し、PAR、PKCE、DPoP を使って FAPI 2.0 Security Profile の RS 受け入れ挙動を確認する。

検証手順では **curl と Python スクリプトを RP として動作させている**。これは [本リポジトリの位置づけ](#本リポジトリの位置づけ) で述べた通り、サーバーサイドで動作する Confidential Client（≒ BFF/Backend RP）を模した簡易検証であり、ブラウザを RP にしているわけではない。本番構成では curl の位置に BFF/Backend アプリケーション、または検証 2 と同様の Kong（RP モード）が入ることになる。

**なお、以下の手順はクライアント認証に `client_secret_post` を使っており、FAPI 2.0 が要求する `private_key_jwt` または mTLS を使っていない**。PAR・PKCE・DPoP・Kong の受け入れ挙動を確認するための簡易検証であり、FAPI 2.0 準拠構成の実証ではない。`private_key_jwt` まで含めた構成は「[検証 2: Kong = RP](#検証-2-kong--rp)」を参照。

> 実装中に踏んだ注意点（Docker メモリ割り当て、Keycloak 内外 URL 統一、Python `requests` の `.localhost` Cookie 問題 など）は「[付録 - 検証中に判明した注意点](#付録---検証中に判明した注意点)」にまとめている。

#### 検証 1 の構成

| コンポーネント | ホスト（外部） | ホスト（コンテナ内部） | 役割 |
| --- | --- | --- | --- |
| Keycloak | `http://keycloak.localhost:9080` | `http://keycloak:8080` | AS（認可サーバー） |
| Kong Gateway | `http://localhost:8000` | — | RS（リソースサーバー） |
| httpbin | — | `http://httpbin` | バックエンド API（エコーサーバー） |

| ファイル | 役割 |
| --- | --- |
| `deck/rs.yaml` | Kong に投入する RS 用設定 |
| `keycloak/realm-import/fapi2-realm.json` の `fapi2-test-client` | RP（curl/Python スクリプトが模す） |
| `scripts/dpop_e2e_verify.py` | 自動検証スクリプト |

#### 検証 1 の環境起動

##### 1. `.env` ファイルを準備する

```bash
cp .env.default .env
```

`.env` を開き、`KONG_LICENSE_DATA` に Kong Enterprise のライセンスを設定する。

##### 2. Docker Compose で全サービスを起動する

```bash
docker compose up -d
```

##### 3. Keycloak の起動を確認する

Keycloak の起動には数十秒かかる。以下のエンドポイントが `200 OK` を返すまで待つ。

```bash
curl -s -o /dev/null -w "%{http_code}" \
  http://keycloak.localhost:9080/realms/fapi2/.well-known/openid-configuration
```

##### 4. deck で Kong に RS 設定を反映する

```bash
deck gateway sync deck/rs.yaml
```

> 検証 2（Kong = RP）に切り替える場合は `deck gateway sync deck/rp.yaml` を再度実行する。両構成は同じ Kong インスタンス上で排他的に動かす設計のため、最後に sync した deck ファイルの設定が有効になる。

#### 検証 1 自動検証スクリプト

手順 5〜12 の全フローを1コマンドで自動実行できるスクリプトを用意している。手動手順の代わりに使える。

```bash
python3 scripts/dpop_e2e_verify.py
```

実行すると以下を順に検証し、全項目が `✓` で終わることを確認する。

```text
✓ DPoP key ready
✓ PKCE generated
✓ request_uri (PAR)
✓ Login form / auth code
✓ DPoP-bound token (cnf.jkt match)
✓ Kong accepted DPoP request → 200 OK
✓ Kong rejected missing DPoP proof → 401
```

スクリプトは `dpop-private.pem` が存在すればそれを再利用し、なければ新規生成する。`cryptography` および `requests` ライブラリが必要である（`pip install cryptography requests`）。

---

#### 検証 1 正常系：FAPI 2.0 フローの実行（手動）

##### 5. DPoP 用の EC キーペアを生成する

DPoP では、クライアントが EC（または RSA）鍵ペアを自前で生成し、Proof JWT の `jwk` ヘッダーに公開鍵を埋め込む。まずキーペアを生成する。

```bash
# 秘密鍵（ES256 用 P-256）
openssl ecparam -name prime256v1 -genkey -noout -out dpop-private.pem

# 公開鍵
openssl ec -in dpop-private.pem -pubout -out dpop-public.pem
```

##### 6. PAR エンドポイントにリクエストして `request_uri` を取得する

PKCE には2つの値が必要だ。認可リクエスト時に送る `code_challenge`（ハッシュ値）と、トークンリクエスト時に送る `code_verifier`（元の乱数）である。

まず `code_verifier` を生成する。
ここではPythonで生成する。
RFC 7636 は 43〜128 文字の URL セーフな文字列を要求する。
`secrets.token_urlsafe(32)` は 32 バイト（256 ビット）の乱数を Base64URL エンコードして返すが、Base64URLエンコードは文字数が約1.33倍に増えるため、結果はちょうど 43 文字になる。

なお、Pythonを使わず`openssl rand -base64 32` を使いたくなるが、openssl は 64 文字ごとに改行を挿入するため避ける。改行が混入すると `code_challenge` の計算結果がずれ、Keycloak に `code not valid` エラーが返る。（trコマンドとか使えばopensslでも改行なしで生成できると思う）

次に `code_challenge` を計算する。S256 方式の定義は以下のとおりだ。

```text
code_challenge = BASE64URL( SHA-256( code_verifier ) )
```

`hashlib.sha256(verifier.encode()).digest()` で SHA-256 ハッシュをバイナリで取得し、`base64.urlsafe_b64encode(...)` で URL セーフ Base64 に変換する。末尾の `.rstrip(b'=')` はパディング文字 `=` の除去で、RFC 7636 が明示的に要求している。

上記の内容を Python のワンライナーで実行し、環境変数 `CODE_VERIFIER` と `CODE_CHALLENGE` に保存する。これをステップ 7 とステップ 8 で使用する。
```bash
eval $(python3 <<'EOF'
import secrets, base64, hashlib
verifier = secrets.token_urlsafe(32)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
print(f'CODE_VERIFIER="{verifier}"')
print(f'CODE_CHALLENGE="{challenge}"')
EOF
)
echo "code_verifier: $CODE_VERIFIER"
echo "code_challenge: $CODE_CHALLENGE"
```

保存した `CODE_VERIFIER` と `CODE_CHALLENGE` を使って、PAR エンドポイントにリクエストを送る。

```bash
PAR_RESPONSE=$(curl -sS -X POST \
  http://keycloak.localhost:9080/realms/fapi2/protocol/openid-connect/ext/par/request \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=fapi2-test-client" \
  -d "client_secret=fapi2-test-secret" \
  -d "response_type=code" \
  -d "scope=openid profile" \
  -d "redirect_uri=https://openidconnect.net/callback" \
  -d "code_challenge=$CODE_CHALLENGE" \
  -d "code_challenge_method=S256" \
  -d "state=$(openssl rand -hex 16)")

echo $PAR_RESPONSE
REQUEST_URI=$(echo $PAR_RESPONSE | jq -r '.request_uri')
```

通常の認可コードフローでは、`client_id` や `redirect_uri` などのパラメータをすべてブラウザのリダイレクト URL に載せる。PAR はこれを逆転させる。パラメータをまずサーバー間通信（バックチャネル）で AS に送りつけ、代わりに短命の参照 ID（`request_uri`）を受け取る。ブラウザにはその参照 ID だけを渡すので、認可パラメータが URL に一切露出しない。FAPI 2.0 はこの PAR を必須としている。

エンドポイントは `/auth` ではなく `/ext/par/request` だ。RFC 9126 は PAR を「ブラウザではなくクライアントサーバーが直接叩く専用エンドポイント」として `/authorize` とは別に定義することを要求している。Keycloak はそのエンドポイントを `/ext/par/request` というパスで実装しており、実際の URL は Discovery ドキュメント（`/.well-known/openid-configuration`）の `pushed_authorization_request_endpoint` フィールドで確認できる。クライアント認証もここで行う。本環境ではテスト用に `client_secret_post`（POSTボディにシークレットを含める方式）を使っているが、FAPI 2.0 の本来の要件はより強い認証方式（`private_key_jwt` または mTLS）を要求する。テスト目的のため Keycloak のクライアント設定でシークレット認証を許可している。

`code_challenge_method=S256` は、トークンリクエスト時に `code_verifier` を受け取った AS が「どのアルゴリズムで `code_challenge` を再計算すればよいか」を知るためのパラメータだ。AS はここで指定された方式で検証するため、省略すると AS 側がどのハッシュ関数を使えばよいかわからない。`S256` は SHA-256 でハッシュすることを意味する。FAPI 2.0 はこの `S256` のみを許可しており、`plain`（ハッシュなしで `code_verifier` をそのまま `code_challenge` として使う）は禁止されている。`state` は FAPI 2.0 では必須ではない。OAuth 2.0 では CSRF 対策として使われてきたが、FAPI 2.0 の Security Profile では「認可リクエストの CSRF 防御手段として state を使わない。PKCE がその役割を担う」と整理されており、必須要件から外れた（FAPI 1.0 では必須だった）。ただし CSRF 対策そのものが不要になるわけではなく、認可フロー開始自体を CSRF から保護する責任はクライアント側にある。用途があるとすれば「ログイン後にどのページに戻るか」といったアプリケーション側の状態管理だ。ここでは動作確認のために付けているが、省略しても FAPI 2.0 の要件は満たせる。


成功すると以下のようなレスポンスが返る。

```json
{"request_uri":"urn:ietf:params:oauth:request_uri:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx","expires_in":600}
```

`request_uri` は `urn:ietf:params:oauth:request_uri:` で始まる不透明な参照 ID だ。中身のパラメータは AS 側に保存されており、クライアントは参照 ID しか受け取らない。この ID はワンタイム使用で、`expires_in` の 600 秒（realm 設定 `parRequestUriLifespan`）以内に一度だけ使える。

##### 7. ブラウザで認可エンドポイントにアクセスしてログインし、認可コードを取得する

> **注意**: `request_uri` はワンタイム使用である。URL を開いた時点で消費されるため、同じ URL をリロード・再利用することはできない。エラーになった場合はステップ 6 からやり直す。なお、`request_uri` の有効期限はデフォルト 600 秒（realm 設定 `parRequestUriLifespan`）であるため、URL 生成後 10 分以内にブラウザで開くこと。

以下のコマンドで URL を生成し、ブラウザで開く。alice（パスワード: `alice-pass`）でログインする。

```bash
# request_uri はコロンを含むため URL エンコードが必要
ENCODED_REQUEST_URI=$(echo "$REQUEST_URI" | jq -Rr @uri)
AUTH_URL="http://keycloak.localhost:9080/realms/fapi2/protocol/openid-connect/auth?client_id=fapi2-test-client&request_uri=${ENCODED_REQUEST_URI}"
echo $AUTH_URL
```

ログイン後、ステップ 6 で指定した `redirect_uri` にリダイレクトされる。`code` パラメータがクエリに含まれているので、その値をコピーして次のステップで使う。

###### インターネットに接続できる環境の場合（`redirect_uri=https://openidconnect.net/callback`）

[openidconnect.net](https://openidconnect.net) は OIDC の動作確認用に公開されているツールで、リダイレクトされてきたクエリパラメータをそのまま画面に表示してくれる。コードを画面から読み取れるので手動検証に便利だ。

###### インターネット接続が制限されている環境の場合

PAR リクエストの `redirect_uri` を `http://localhost:8000/anything` に変更する。ステップ 8 のトークンリクエストも同じ値に合わせること。

```bash
  -d "redirect_uri=http://localhost:8000/anything" \
```

ログイン後、ブラウザは `http://localhost:8000/anything?code=...&session_state=...&iss=...` にリダイレクトされる。Kong は認証ヘッダーがないため 401 を返すが、**ブラウザのアドレスバーに表示される URL** に `code` パラメータが含まれているのでそこからコピーできる。Keycloak はリダイレクト先が実際に応答するかどうかは検証しないため、Kong が 401 を返しても認可コードの取得には影響しない。

> **注意**: 認可コードは **5 分以内**（`accessCodeLifespan: 300`）にトークンリクエストで消費すること。また `AUTH_CODE` と `CODE_VERIFIER` は必ず**同じセッション**のものを使う。ステップ 6 をやり直した場合は認可フローも最初からやり直す。

```bash
AUTH_CODE=<取得した認可コード>
```

##### 8. DPoP Proof JWT を生成し、トークンエンドポイントで認可コードを交換する

DPoP Proof JWT は「このリクエスト専用の署名」だ。通常の Bearer トークンと違い、DPoP はトークンを使うたびに秘密鍵で新しい Proof を生成し、それをリクエストに添付する。サーバー側はこの Proof の署名を検証することで「トークンの正当な保有者が今まさにリクエストしている」ことを確認する。

Proof JWT は以下の構造を持つ。

```text
ヘッダー: {
  "typ": "dpop+jwt",   ← このトークン種別が DPoP Proof であることを示す
  "alg": "ES256",      ← 署名アルゴリズム
  "jwk": { ... }       ← 公開鍵をそのまま埋め込む（AS が別途取得しに行かなくてよい）
}
ペイロード: {
  "jti": "<ランダム値>",  ← リプレイ攻撃防止。毎回異なる値にする
  "htm": "POST",          ← このProofが有効なHTTPメソッド
  "htu": "<トークンURL>", ← このProofが有効なURL（他のエンドポイントでは使えない）
  "iat": <現在時刻>       ← 発行時刻。古すぎるProofはASに拒否される
}
```

`htm` と `htu` でリクエストの宛先に縛られているため、傍受した Proof を別のエンドポイントや別のメソッドで再利用することができない。`jti` がユニークなのは同じ Proof を二重送信するリプレイ攻撃を防ぐためだ。

Python でプルーフを生成し、curl は別コマンドで実行する。

cryptography がない場合は事前にインストールする。
```bash
pip install cryptography
```
以下を実行してProof JWTを生成し、環境変数 `DPOP_PROOF` に保存する。
```bash
# ① DPoP Proof を生成して変数に保存
DPOP_PROOF=$(python3 <<'EOF'
import json, base64, os, time
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# 秘密鍵を読み込み、公開鍵の x・y 座標を JWK 形式に変換する
priv = load_pem_private_key(open('dpop-private.pem', 'rb').read(), password=None)
pub  = priv.public_key().public_numbers()
jwk  = {"kty":"EC","crv":"P-256",
        "x":b64url(pub.x.to_bytes(32,'big')),
        "y":b64url(pub.y.to_bytes(32,'big'))}

# ヘッダーに公開鍵を埋め込む。AS はここから取り出して署名を検証し JWK Thumbprint を計算する
header  = {"typ":"dpop+jwt","alg":"ES256","jwk":jwk}
payload = {"jti":b64url(os.urandom(16)),   # ユニークID（リプレイ防止）
           "htm":"POST",                    # このProofはPOSTにのみ有効
           "htu":"http://keycloak.localhost:9080/realms/fapi2/protocol/openid-connect/token",
           "iat":int(time.time())}          # 発行時刻（古すぎると拒否される）

h = b64url(json.dumps(header, separators=(',',':')))
p = b64url(json.dumps(payload, separators=(',',':')))
signing_input = f"{h}.{p}"

# Python の cryptography ライブラリは DER 形式で署名を返すが、
# JWT の ES256 は r と s を 32 バイトずつ連結した raw 形式を要求する
der_sig = priv.sign(signing_input.encode(), ECDSA(SHA256()))
r, s = decode_dss_signature(der_sig)
print(f"{signing_input}.{b64url(r.to_bytes(32,'big') + s.to_bytes(32,'big'))}")
EOF
)
```

JWT の生成手順を整理すると以下のようになる。

```text
① ヘッダーと ペイロードをそれぞれ JSON にシリアライズし、BASE64URL エンコードする
   h = BASE64URL( JSON(header) )
   p = BASE64URL( JSON(payload) )

② ドットで結合したものが署名対象（signing_input）
   signing_input = h + "." + p

③ signing_input を秘密鍵（P-256）で署名する
   ECDSA の署名結果は r と s という2つの整数のペアになる。
   r は「署名時に使った乱数点の x 座標から導いた値」、
   s は「メッセージのハッシュ・秘密鍵・r を組み合わせて計算した値」だ。
   この2つを揃えることで「秘密鍵を持つ者がこの内容に同意した」ことを証明できる。
   検証側は公開鍵と r, s を使って数学的に確認するだけでよく、秘密鍵は一切不要だ。

   → cryptography ライブラリは r と s を ASN.1 DER 形式（各値の長さ情報も含む構造体）で返す
   → JWT の ES256 は DER ではなく r と s を 32 バイトずつ素直に並べた raw 形式を要求する
   → decode_dss_signature() で DER を解析して r, s の整数を取り出し、
      それぞれ 32 バイトのバイト列に変換して連結する（合計 64 バイト）

④ 署名を BASE64URL エンコードして末尾に付ける
   DPoP Proof JWT = h + "." + p + "." + BASE64URL(r || s)
```

JWT 全体は `.` 区切りの3パートで構成される。これはアクセストークンや ID Token と同じ構造だ。DPoP Proof が特殊なのは、ヘッダーに公開鍵（`jwk`）が含まれている点と、ペイロードが「このリクエスト専用」の情報だけで構成されている点だ。

DPoP Proof の準備ができたら、トークンエンドポイントに認可コードを送って、アクセストークンに交換する。このリクエストが FAPI 2.0 の肝になる部分で、OAuth 2.0 の通常のコード交換に DPoP バインディングが加わった形だ。

```bash
TOKEN_RESPONSE=$(curl -sS -X POST \
  http://keycloak.localhost:9080/realms/fapi2/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "DPoP: $DPOP_PROOF" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=https://openidconnect.net/callback" \
  -d "client_id=fapi2-test-client" \
  -d "client_secret=fapi2-test-secret" \
  -d "code_verifier=$CODE_VERIFIER")

echo $TOKEN_RESPONSE | jq .
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')
```
各パラメータの意味を整理しておく。

- **`grant_type=authorization_code`** — OAuth 2.0 の認可コードグラントを使うことを宣言する。Keycloak はこれを見てコード交換モードで動作する。
- **`code=$AUTH_CODE`** — ステップ 7 で取得した認可コード。一回限りの使い捨てで、消費済みのコードを再送するとエラーになる。
- **`redirect_uri`** — PAR リクエスト（ステップ 6）で指定した値と **完全一致** する必要がある。Keycloak は受け取ったリクエストを PAR で保存した内容と突き合わせ、値が異なればトークンを発行しない。これは「認可コードを横取りして別のクライアントがトークンを取ろうとする攻撃」を防ぐための検証だ。ここでは `https://openidconnect.net/callback` を使っているが、インターネット接続が制限されている環境では `http://localhost:8000/anything` に変更すること。
- **`client_id` / `client_secret`** — `client_secret_post` 方式によるクライアント認証だ。リクエストボディにシークレットを直接含めるシンプルな方法で、FAPI 2.0 は本来 `private_key_jwt`（クライアント自身の秘密鍵で署名した JWT）か mTLS を要求している。`client_secret_post` は検証目的の妥協点であり、本番運用では使わない。
- **`code_verifier=$CODE_VERIFIER`** — PKCE の検証用の値だ。ステップ 6 で生成した元のランダム文字列を送る。Keycloak はこれを受け取って `BASE64URL(SHA-256(code_verifier))` を計算し、PAR リクエスト時に受け取った `code_challenge` と一致するか確認する。一致すれば「認可コードを申請したクライアントと、今トークンを要求しているクライアントが同一人物だ」と証明できる。
- **`DPoP: $DPOP_PROOF` ヘッダー** — これが DPoP バインドトークン発行のトリガーになる。Keycloak は Proof JWT のヘッダーに埋め込まれた `jwk`（公開鍵）を使って署名を検証し、`htm` が `POST`・`htu` がトークンエンドポイントの URL であることを確認する。検証が通ると、公開鍵の JWK Thumbprint を計算して `cnf.jkt` としてアクセストークンに埋め込む。これ以降、このトークンは「`cnf.jkt` に対応する秘密鍵を持つ者しか使えない」という制約を持つ。


トークンペイロードをデコードして cnf.jkt を確認する。
`cnf.jkt` は「このトークンを使えるのは、この JWK Thumbprint の鍵を持つ者だけ」という束縛を表す。
ここに値が入っていれば DPoP バインドが成功している。
```sh
echo $ACCESS_TOKEN | jq -R 'split(".")[1] | @base64d | fromjson | {cnf, typ}'
```

`cnf.jkt` に値が入っていれば成功だ。`cnf.jkt` は公開鍵を正規化して SHA-256 でハッシュした値（JWK Thumbprint）で、Keycloak がトークン発行時に Proof の `jwk` から計算して埋め込む。Kong はリクエストを受け取ったときに DPoP Proof の公開鍵から同じ Thumbprint を計算し、この値と照合する。

なお、JWT ペイロード内の `token_type` は Keycloak のバージョンによって `null` になることがある。これは問題ではない。RFC 9449 が Resource Server（Kong）に要求する検証は `cnf.jkt` と DPoP Proof の鍵一致であり、JWT ペイロード内の `token_type` クレームは検証対象ではない。`token_type: DPoP` はトークンエンドポイントの HTTP レスポンスボディに現れるもので、クライアントへの「DPoP proof を添えて使え」という指示だ。

> `cnf.jkt` が `null` の場合、Keycloak がトークンに DPoP バインディングを付与していない。`DPOP_PROOF` が空でないにもかかわらず `cnf.jkt` が null の場合は、Keycloak の DPoP 設定を確認する。introspection レスポンスで直接確認する場合は以下を実行する。
>
> ```bash
> curl -s -X POST \
>   http://keycloak.localhost:9080/realms/fapi2/protocol/openid-connect/token/introspect \
>   -H "Content-Type: application/x-www-form-urlencoded" \
>   -d "token=$ACCESS_TOKEN" \
>   -d "client_id=kong" \
>   -d "client_secret=kong-secret" | jq '{active, cnf}'
> ```

##### 9. Kong 経由でバックエンド API を呼び出す

API 呼び出し用の DPoP Proof はトークンリクエスト時とは別に生成する。
```bash
DPOP_PROOF_API=$(ACCESS_TOKEN="$ACCESS_TOKEN" python3 <<'EOF'
import json, base64, os, time, hashlib
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

priv = load_pem_private_key(open('dpop-private.pem', 'rb').read(), password=None)
pub  = priv.public_key().public_numbers()
jwk  = {"kty":"EC","crv":"P-256",
        "x":b64url(pub.x.to_bytes(32,'big')),
        "y":b64url(pub.y.to_bytes(32,'big'))}

ath = b64url(hashlib.sha256(os.environ['ACCESS_TOKEN'].encode()).digest())

header  = {"typ":"dpop+jwt","alg":"ES256","jwk":jwk}
payload = {"jti":b64url(os.urandom(16)),
           "htm":"GET",
           "htu":"http://localhost:8000/anything",
           "iat":int(time.time()),
           "ath":ath}

h = b64url(json.dumps(header, separators=(',',':')))
p = b64url(json.dumps(payload, separators=(',',':')))
signing_input = f"{h}.{p}"

der_sig = priv.sign(signing_input.encode(), ECDSA(SHA256()))
r, s = decode_dss_signature(der_sig)
print(f"{signing_input}.{b64url(r.to_bytes(32,'big') + s.to_bytes(32,'big'))}")
EOF
)
```

コードの骨格（鍵の読み込み・JWK 構築・b64url 関数・DER→raw 変換）はステップ 8 と同じなので省略し、ここではステップ 8 との差分だけを説明する。

**`htm`・`htu` の変更**

```json
"htm": "GET",
"htu": "http://localhost:8000/anything",
```

ステップ 8 では `htm: POST`、`htu` が Keycloak のトークンエンドポイントだった。DPoP Proof は `htm`＋`htu` の組み合わせに縛られているため、トークン取得時の Proof をそのまま API 呼び出しに使い回すことはできない。Kong は受け取った Proof の `htm`・`htu` が実際のリクエストのメソッド・URL と一致するか検証し、不一致なら拒否する。

**`ath` クレーム（RFC 9449 §4.2）**

```python
ath = b64url(hashlib.sha256(os.environ['ACCESS_TOKEN'].encode()).digest())
```

`ath` は「この Proof がどのアクセストークンに対して作られたか」を示す。アクセストークンの ASCII 文字列を UTF-8 でエンコードし、SHA-256 ハッシュを取って base64url にしたものだ。これにより Proof とトークンが 1 対 1 で紐付けられ、攻撃者が別のトークンを手に入れたとしても、この Proof と組み合わせて使うことができなくなる。トークンリクエスト時には `ath` は不要だった（まだアクセストークンが存在しないため）。

`ACCESS_TOKEN` を `os.environ` 経由で渡しているのは、Python ヒアドキュメント内では bash の変数展開（`$ACCESS_TOKEN`）が効かないためだ。`ACCESS_TOKEN="$ACCESS_TOKEN" python3 <<'EOF'` の形で親シェルの変数を子プロセスの環境変数として明示的に渡している。

作成した `DPOP_PROOF_API` をリクエストヘッダー `DPoP` に添えて、Kong 経由で httpbin のエンドポイントを呼び出す。Kong は Proof を検証し、トークンの `cnf.jkt` と Proof の鍵が一致すればリクエストを httpbin に転送する。
```sh
curl -i http://localhost:8000/anything \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF_API"
```

httpbin のレスポンス（リクエストヘッダーのエコー）が返れば成功である。レスポンス内の `headers` フィールドで `Authorization` ヘッダーが確認できる。

#### 検証 1 異常系：拒否されることを確認する

##### 10. DPoP Proof なしでアクセスする → 401 を確認する

DPoP Proof ヘッダーを省略すると、Kong が「sender-constrained token なのに Proof がない」と判断して 401 を返す。

```bash
curl -i http://localhost:8000/anything \
  -H "Authorization: DPoP $ACCESS_TOKEN"
# → HTTP/1.1 401 Unauthorized
```

##### 11. PAR なしで認可エンドポイントに直接アクセスする → Keycloak が拒否することを確認する

Keycloak の `fapi2-test-client` は `require.pushed.authorization.requests: true` が設定されているため、`request_uri` を使わない通常の認可リクエストは拒否される。

```bash
# request_uri を使わず直接パラメータを渡す（PAR なし）
curl -i "http://keycloak.localhost:9080/realms/fapi2/protocol/openid-connect/auth?\
client_id=fapi2-test-client&response_type=code&scope=openid&\
redirect_uri=https://openidconnect.net/callback&\
code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"
# → エラーレスポンス（Pushed Authorization Request is required）
```

##### 12. グループ未所属の charlie のトークンで Kong にアクセスする

charlie は `fapi2-users` Consumer Group に属していないが、現在の `deck/rs.yaml` には ACL プラグインが設定されていないため、グループ未所属を理由に自動的に 401 になるわけではない。グループベースのアクセス制御を実際に動作させるには ACL プラグインの追加が必要だ。手順 6〜8 を charlie のクレデンシャル（パスワード: `charlie-pass`）で繰り返すことで、Keycloak の認証は通るが Kong 側に Consumer Group による制限がないことを確認できる。

```bash
curl -i http://localhost:8000/anything \
  -H "Authorization: DPoP $CHARLIE_ACCESS_TOKEN" \
  -H "DPoP: $CHARLIE_DPOP_PROOF"
# → HTTP/1.1 401 Unauthorized
```

---

### 検証 2: Kong = RP

検証 2 では Kong を **FAPI 2.0 Confidential Client（OIDC RP）に近い構成** で動作させる。Kong がブラウザを終端し、**PAR / JAR / private_key_jwt** を `openid-connect` プラグインで実装する。Backend（httpbin）は OAuth/OIDC を一切意識せず、Kong から渡される `x-userinfo-*` ヘッダーを受け取るだけでよい。

ただし **JARM（署名済み認可レスポンス）と DPoP（sender-constrained token）は Kong の openid-connect プラグインの仕様上、本検証では到達できなかった**。詳細は「[検証 2（Kong = RP）の補足](#検証-2kong--rpの補足)」を参照。

> 実装中に踏んだ注意点（YAML 1.1 の `n:` boolean 衝突、`jwks_endpoint` キー名、DPoP / JARM の RP 側未対応 など）は「[付録 - 検証中に判明した注意点](#付録---検証中に判明した注意点)」にまとめている。

#### 検証 2 の構成

| コンポーネント | ホスト（外部） | ホスト（コンテナ内部） | 役割 |
| --- | --- | --- | --- |
| Keycloak | `http://keycloak.localhost:9080` | `http://keycloak:8080` | AS（認可サーバー） |
| Kong Gateway | `http://localhost:8000` | — | **RP（OIDC 終端）** |
| httpbin | — | `http://httpbin` | バックエンド API（OAuth 非対応のレガシー Backend を模す） |

| ファイル | 役割 |
| --- | --- |
| `deck/rp.yaml` | Kong に投入する RP 用設定（authorization_code + session、PAR/JAR/private_key_jwt） |
| `keys/kong-rp-private.pem` / `.jwk.json` / `kong-rp-public.jwks.json` | Kong が `private_key_jwt` と JAR で使う PS256 鍵ペア（公開鍵は Keycloak 側にも登録） |
| `keycloak/realm-import/fapi2-realm.json` の `kong-rp-client` | Kong（RP）に対応する Keycloak クライアント定義 |
| `scripts/rp_e2e_verify.py` | 自動検証スクリプト（curl 相当の HTTP follow-redirects で browser を模す） |

> 鍵ペア（`keys/kong-rp-*.pem`, `*.jwk.json`, `*.jwks.json`）は **テスト用** として Git にコミットしている。本番では HSM・Vault・環境変数経由など安全な経路で配布すること。再生成したい場合は `cd keys && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out kong-rp-private.pem && openssl rsa -in kong-rp-private.pem -pubout -out kong-rp-public.pem && python3 generate_jwks.py` を実行し、生成された JWKS を `fapi2-realm.json` の `kong-rp-client.attributes.jwks.string` と `deck/rp.yaml` の `client_jwk` に反映する。

#### 検証 2 の環境起動

検証 1 と Keycloak / Docker Compose のセットアップは共通である。検証 1 の手順 1〜3 を済ませた状態から続ける。

##### 1. Kong に RP 設定を反映する

```bash
deck gateway sync deck/rp.yaml
```

> 検証 1（RS）から検証 2（RP）に切り替えるとき、`deck gateway sync` は同期前の state（RS の `/anything` ルート）を削除して RP の `/protected` ルートに置き換える。両方を残したい場合は手動で deck ファイルをマージする必要があるが、本リポジトリでは「都度切り替えて検証する」運用を前提とする。
>
> sync 直後は Kong の worker reload にわずかなラグがあり、最初の 1〜2 秒は新しいルートが 404 を返すことがある。検証スクリプトを実行するときは sync 後に数秒待つこと（あるいは 404 が返ったら 1 度リトライする）。

##### 2. ルートが投入されたことを確認する

```bash
curl -s http://localhost:8001/services/rp-protected | jq '.name, .host'
# → "rp-protected"
# → "httpbin"
```

#### 検証 2 自動検証スクリプト

ブラウザの代わりに Python の `requests` でリダイレクトを follow しながら、Kong の RP フロー全体を一気通貫で確認できるスクリプトを用意している。

```bash
python3 scripts/rp_e2e_verify.py
```

スクリプトは以下を順に検証する。

```text
[1] GET /protected (unauthenticated)
    → 302 redirect to Keycloak
    ✓ PAR engaged: request_uri=urn:ietf:params:oauth:request_uri:...
    ✓ Authorize URL points to Keycloak: keycloak.localhost:9080/...
[2] Fetch Keycloak login form
    ✓ Form action: ...
[3] POST credentials (alice)
    → 302 redirect to Kong with auth code
    ⚠ Plain 'code' returned (not JARM).  ← JARM 未使用（Kong 制約のため）
[4] Follow callback into Kong (token exchange + upstream forward)
    → 200 with httpbin echo
    ✓ Session cookie set: kong_rp_session
    ✓ Upstream backend (httpbin) returned a response — full RP flow completed
    ✓ Upstream received userinfo headers: ['X-Userinfo-Sub', 'X-Userinfo-Username', 'X-Userinfo-Groups']
```

各チェックが何を検証しているかは以下の通り。

| ステップ | 検証内容 | FAPI 2.0 要件との対応 |
| --- | --- | --- |
| [1] PAR engaged | 初回アクセス時の Authorize URL に `request_uri` が含まれていることを確認 | Security Profile: PAR 必須 |
| [3] Plain `code` 受信 | コールバック URL に `code=...` が含まれていることを確認。JARM 不採用の本検証では `response=<JWT>` ではなく平文 `code` で受信する | （Message Signing の signed authorization responses option は **未採用**） |
| [4] Session cookie + Upstream forward | Kong が token endpoint を叩いて access_token を取得し、セッションを確立、Backend にリクエストを転送することを確認 | RP 機能（コード交換＋セッション） |
| [4] Userinfo headers | Backend（httpbin）が Kong から渡されたユーザー情報を受け取れることを確認 | RP 機能（Backend は OAuth 非対応で OK） |

> Kong の openid-connect プラグインは、コールバック・コード交換・upstream へのフォワードを **同一 HTTP トランザクション** で処理する。検証 1（RS）のように「302 で /protected に戻ってから再度 GET」というステップは存在せず、ステップ [4] の 200 レスポンスがそのまま httpbin の echo 結果を含んでいる。
>
> **注意**: 検証スクリプトは `request_uri` の存在やセッション Cookie の発行までを確認するが、PAR リクエストで実際に `private_key_jwt` 認証が使われたか、JAR の署名が PS256 で行われたかは、Keycloak のログ（`docker logs fapi2-keycloak`）や admin API で `kong-rp-client` のセッション情報を確認する必要がある。

#### 検証 2 ブラウザでの手動確認

実際のブラウザでフローを観察したい場合は以下の手順で操作する。スクリプトでは見えない「JARM レスポンスの中身」「Cookie の `Secure`/`HttpOnly` 属性」「ログアウトの挙動」などを目視確認できる。

##### 1. ブラウザで `/protected` にアクセスする

```text
http://localhost:8000/protected
```

ブラウザが Keycloak のログイン画面にリダイレクトされる。URL に `request_uri=urn:ietf:params:oauth:request_uri:...` が含まれていることを確認する（PAR が有効）。

##### 2. alice / alice-pass でログインする

ログイン成功後、Keycloak がブラウザを Kong のコールバック URL（`/protected?code=<認可コード>&state=<state>`）にリダイレクトする。Kong は受け取った認可コードを Keycloak のトークンエンドポイントへ private_key_jwt 認証で交換する。

> 本検証では JARM・DPoP は使用していない（Kong プラグインの制約による、詳細は[検証 2 の補足](#検証-2kong--rpの補足)）。Message Signing 仕様の signed authorization responses option を採用した完全な構成では、コールバック URL は `/protected?response=<JARM JWT>` の形になる。

##### 3. Kong からのレスポンスを確認する

最終的にブラウザは `/protected` 上で httpbin の echo レスポンスを表示する。レスポンス JSON の `headers` フィールドに `X-Userinfo-Sub`・`X-Userinfo-Username`・`X-Userinfo-Groups` が含まれていれば成功。

##### 4. Cookie を確認する

ブラウザの開発者ツールで `kong_rp_session` Cookie の属性を確認する。`HttpOnly`・`SameSite=Lax` が付いていることを確認。`Secure` 属性は本検証では HTTP（非 HTTPS）でアクセスしているため付かない（本番運用では HTTPS にして `session_cookie_secure: true` にすること）。

##### 5. ログアウト

```text
http://localhost:8000/protected/logout
```

`logout_uri_suffix: /logout` の設定により、Kong がセッションを破棄し、Keycloak の logout エンドポイントを叩いてアクセストークンを revoke する。

---

### 検証 3: Kong = RP × mTLS

検証 3 では **検証 2 で到達できなかった sender-constrained access token** を **mTLS 方式（RFC 8705）** で実現する。Kong は Keycloak の HTTPS（mTLS）エンドポイントに対してクライアント証明書を提示し、Keycloak はその証明書の SHA-256 thumbprint を `cnf.x5t#S256` クレームに埋め込んでアクセストークンを発行する。FAPI 2.0 Security Profile が sender-constrained token として認める「DPoP **または** mTLS」のうち、Kong の `openid-connect` プラグインで実装できるのは mTLS 方式である。

> 実装中に踏んだ注意点（Certificate エンティティの UUID 要件、`KC_TRUSTSTORE_PATHS` への切替、`KONG_LUA_SSL_TRUSTED_CERTIFICATE`、`x509.subjectdn` の正規表現マッチ、JWKS キャッシュ問題 など）は「[付録 - 検証中に判明した注意点](#付録---検証中に判明した注意点)」にまとめている。

#### mTLS の適用範囲（どこと、どこの間？）

検証 3 で「mTLS」と呼んでいるのは **Kong（RP）と Keycloak（AS）の間だけ** である。本検証の通信全体を切り出すと次のようになる。

```text
[ブラウザ]  ──── HTTP (plain) ────>  [Kong :8000]  ──── HTTP (plain) ───>  [httpbin]
                                          │
                                          │ ↑↓  ★mTLS（HTTPS + 双方向クライアント証明書認証）
                                          │
                                          ↓
                                      [Keycloak :9443]
                                          - PAR endpoint（mtls_endpoint_aliases）
                                          - token endpoint（mtls_endpoint_aliases）
```

| 区間 | プロトコル | mTLS か？ | 理由 |
| --- | --- | --- | --- |
| **ブラウザ ↔ Kong**（`http://localhost:8000/protected-mtls`） | HTTP | ❌ 平文 | PoC 用に簡略化。本番では Kong の Listener を HTTPS（8443）にして、ブラウザ向けにはサーバー認証のみの TLS を張る（**mTLS は不要**、ユーザーは証明書を持たないため） |
| **Kong ↔ Keycloak**（`https://keycloak.localhost:9443/...`） | HTTPS + mTLS | ✅ **本検証の本丸** | Kong が `tls_client_auth_cert_id` で指定したクライアント証明書を提示し、Keycloak は `KC_TRUSTSTORE_PATHS` の CA で検証する（同時に Kong も Keycloak のサーバー証明書を **`KONG_LUA_SSL_TRUSTED_CERTIFICATE` 経由で読み込んだ CA** で検証する、双方向認証） |
| **Kong ↔ httpbin（Backend）** | HTTP | ❌ 平文 | Kong と Backend の間は信頼境界の内側として平文。本番でも一般に Service Mesh（mTLS）や TLS 終端の設計に応じる |

つまり **検証 3 の mTLS は「Kong が AS に対して『私はこの証明書を持つクライアントです』と暗号学的に名乗るための経路」**であり、ユーザー側（ブラウザ）には一切影響しない。FAPI 2.0 が要求する sender-constrained token は **AS が発行時に Kong のクライアント証明書 thumbprint をトークンに埋め込む** ことで実現されるので、AS との **クライアント認証経路が mTLS** であれば成立する。

> **`deck/rp-mtls.yaml` の Service / Route が HTTPS 設定を持っていない理由**: 上述の通り、Kong の **Listener 側（ブラウザ向け）** には mTLS は不要。`tls_client_auth` で参照される Certificate エンティティは **Kong が外向きに（Keycloak へ）クライアントとして提示する** ためのもので、Service の `url: http://httpbin/anything` や Route の `protocols: [http, https]` とは独立に動く。`deck/rp-mtls.yaml` が一見すると HTTP しか出てこないように見えるのは、この理由による。

#### 検証 3 の構成

| コンポーネント | エンドポイント | 役割 |
| --- | --- | --- |
| Keycloak | HTTP `:9080` / **HTTPS+mTLS `:9443`** | AS。HTTPS リスナ（9443）を追加し、mTLS で `tls.client.certificate.bound.access.tokens` を有効にした `kong-rp-mtls-client` を配置 |
| Kong Gateway | `:8000`（route `/protected-mtls`） | RP。`tls_client_auth` で Keycloak と相互 TLS 接続し、`cnf.x5t#S256` 付きトークンを取得 |
| httpbin | — | Backend |

| ファイル | 役割 |
| --- | --- |
| `tls/ca-cert.pem` / `ca-key.pem` | PoC 用ローカル CA（Keycloak と Kong の両方が信頼） |
| `tls/keycloak-cert.pem` / `keycloak-key.pem` | Keycloak HTTPS サーバー証明書（CN=keycloak.localhost、SAN 付き） |
| `tls/kong-rp-mtls-cert.pem` / `kong-rp-mtls-key.pem` | Kong RP のクライアント証明書 |
| `tls/generate.sh` | 上記 4 種類の鍵 / 証明書を再生成するスクリプト |
| `deck/rp-mtls.yaml` | Kong に投入する RP（mTLS）設定。Certificate / CACertificate エンティティと `tls_client_auth` プラグイン設定 |
| `keycloak/realm-import/fapi2-realm.json` の `kong-rp-mtls-client` | `clientAuthenticatorType: client-x509` + `tls.client.certificate.bound.access.tokens=true` |
| `scripts/rp_mtls_e2e_verify.py` | 自動検証（PAR・mTLS トークン取得・introspection で `cnf.x5t#S256` の一致確認） |

> 鍵 / 証明書は **PoC 用** として Git にコミットしている。本番運用では HSM / Vault / cert-manager 等から配布すること。再生成は `cd tls && ./generate.sh` を実行し、出力される SHA-256 fingerprint を必要に応じて記録する。

#### 検証 3 の環境起動

検証 1・2 と同じ docker-compose を再利用するが、Keycloak の HTTPS リスナ（ポート `9443`）と PKCS12 トラストストアの読み込みが追加で有効になっている。`docker-compose.yaml` を修正したあとに再起動する場合は次のように行う。

```bash
docker compose down -v   # 既存 realm を初期化（HTTPS 設定の取り込み）
docker compose up -d
```

##### 1. Kong に mTLS 用 RP 設定を反映する

```bash
deck gateway sync deck/rp-mtls.yaml
```

`deck/rp-mtls.yaml` には Certificate / CACertificate エンティティが含まれているため、初回 sync で 5 オブジェクト（Certificate, CACertificate, Service, Route, Plugin）が作成される。

> Kong コンテナにはローカル CA（`tls/ca-cert.pem`）が `KONG_LUA_SSL_TRUSTED_CERTIFICATE` 経由で渡されている。コンテナを再起動した直後は openid-connect プラグインの JWKS キャッシュがリセットされるが、Keycloak 側の鍵生成タイミングと衝突した場合 `suitable jwk was not found` というエラーが出ることがある。その場合は `docker compose restart kong` で Kong を再起動するとキャッシュが綺麗になり問題が解消する。

##### 2. mTLS ルートが投入されたことを確認する

```bash
curl -s http://localhost:8001/services/rp-mtls-protected | jq '.name, .host'
# → "rp-mtls-protected"
# → "httpbin"
```

#### 検証 3 自動検証スクリプト

```bash
python3 scripts/rp_mtls_e2e_verify.py
```

期待する出力は次の通り。**最後の `cnf.x5t#S256` 一致が証明書バインドの実証** である。

```text
[1] GET /protected-mtls (unauthenticated)
    ✓ PAR engaged: request_uri=urn:ietf:params:oauth:request_uri:...
    ✓ Authorize URL points to Keycloak: keycloak.localhost:9080/...
[2] Fetch Keycloak login form
    ✓ Form action: ...
[3] POST credentials (alice)
    → 302 callback to Kong with auth code
[4] Follow callback into Kong (mTLS token exchange + upstream forward)
    → 200 with httpbin echo
    ✓ Upstream backend (httpbin) returned a response
    ✓ Upstream received userinfo headers: ['X-Userinfo-Sub', 'X-Userinfo-Username', 'X-Userinfo-Groups']
    ✓ access_token forwarded to upstream
[5] Introspect access_token and check cnf.x5t#S256
    ✓ Kong client cert SHA-256 thumbprint (b64url): f56NW1NJOnht_aodanu-Rsl180jk8Bt-mK9Er2eiafc
    ✓ cnf.x5t#S256 == client cert thumbprint  → token is sender-constrained ✓

  All checks completed — Kong RP issued an mTLS-bound token.
```

##### 各ステップの確認事項

| ステップ | 確認内容 | 対応する FAPI 2.0 要件 |
| --- | --- | --- |
| [1] PAR engaged | 認可リクエストが PAR エンドポイント経由（HTTPS+mTLS）でプッシュされる | Security Profile: PAR 必須 |
| [4] mTLS token exchange | Kong が tls_client_auth で Keycloak `:9443` と相互 TLS 接続し、code を交換 | Security Profile: 強いクライアント認証（`tls_client_auth`） |
| [4] Userinfo headers | Backend が `x-userinfo-*` ヘッダーでユーザー情報を受け取る | RP 機能 |
| [5] cnf.x5t#S256 一致 | アクセストークンが Kong のクライアント証明書 thumbprint にバインドされている | **Security Profile: sender-constrained token（mTLS 方式、RFC 8705）** |

#### 検証 3 で押さえている FAPI 2.0 要件

| 要件 | 検証 3 |
| --- | --- |
| 認可コードフロー（`response_type=code` のみ） | ✅ |
| PKCE（S256） | ✅ |
| PAR | ✅（HTTPS+mTLS PAR エンドポイント経由） |
| クライアント認証 `private_key_jwt` または `mTLS` | ✅（mTLS / `tls_client_auth`） |
| sender-constrained token | ✅（mTLS、`cnf.x5t#S256`） |
| JWT 署名アルゴリズム（PS256/ES256/EdDSA） | ✅（PS256） |
| Message Signing：JAR | ⚠️ 本検証では未使用（`require_signed_request_object` を有効にすると Kong が `client_jwk` を要求するため、tls_client_auth と併用するには追加設計が必要） |
| Message Signing：JARM | ❌（Kong プラグインの制約は検証 2 と同じ） |

検証 3 で **Security Profile の必須要件は実質的に揃った** 形になる。Message Signing（JAR/JARM）まで踏み込むには Kong 側でクライアント JWK 鍵を別途追加する必要があるが、これは将来課題として残す。

---

## 付録 - Kong Gateway と Keycloak の設定解説

ここでは `deck/rs.yaml`（検証 1）、`deck/rp.yaml`（検証 2）、`deck/rp-mtls.yaml`（検証 3）、および `keycloak/realm-import/fapi2-realm.json`（Keycloak）の各設定値が何を意味し、FAPI 2.0 のどの要件に対応するかを整理する。

### Kong Gateway（deck/rs.yaml）

#### openid-connect プラグイン

```yaml
auth_methods:
  - introspection
```

Kong がトークンを検証する方式として introspection を選択している。Kong はアクセストークンを受け取るたびに Keycloak の introspection エンドポイントへ問い合わせ、トークンの有効性・クレームを確認する。JWT 署名検証（`bearer_jwt_auth`）を使う方法もあるが、introspection はトークンのリアルタイム失効が反映される利点がある。

```yaml
issuer: ${{ env "DECK_ISSUER" }}
using_pseudo_issuer: true
```

`using_pseudo_issuer: true` は Kong に「この issuer から Discovery を行わない」と指示するフラグだ。通常 Kong は issuer URL から `/.well-known/openid-configuration` を取得して各エンドポイントを自動解決するが、このフラグを立てると discovery を行わない。そのため `introspection_endpoint` を明示設定している。`issuer` の値はトークンの `iss` クレームとの対応付けに使われる。

このフラグが必要な理由は、本環境の Docker ネットワーク構成にある。Keycloak は `KC_HOSTNAME: http://keycloak.localhost:9080` で起動しているため、発行するすべてのトークンの `iss` クレームは `http://keycloak.localhost:9080/realms/fapi2` になる。一方、ポート 9080 は Docker ホスト側のポートマッピングであり、Kong コンテナの内部からは到達できない。Kong が Keycloak に実際に通信できるのは `http://keycloak:8080`（Docker 内部ネットワーク）経由だ。

`using_pseudo_issuer` なしで Discovery を使おうとすると、Kong は到達可能な内部 URL（`keycloak:8080`）に Discovery を試みるが、Discovery ドキュメントの `issuer` フィールドは公開 URL（`keycloak.localhost:9080`）を返す。Kong はこの不一致を検出してエラーにする。`using_pseudo_issuer: true` で Discovery を無効にし、`introspection_endpoint` を内部 URL で明示することでこの問題を回避している。

```yaml
introspection_endpoint: ${{ env "DECK_INTROSPECTION_ENDPOINT" }}
client_id:
  - ${{ env "DECK_CLIENT_ID" }}
client_secret:
  - ${{ env "DECK_CLIENT_SECRET" }}
client_auth:
  - client_secret_post
introspection_endpoint_auth_method: client_secret_post
```

introspection エンドポイントへのリクエストには Kong 自身のクライアント認証が必要だ。`client_auth: client_secret_post` は POST ボディにクライアントIDとシークレットを含めて送る方式で、本環境では Keycloak の `kong` クライアントに対して認証している。FAPI 2.0 Security Profile が要求するクライアント認証（`private_key_jwt` または mTLS）はエンドユーザー向けクライアント（`fapi2-test-client`）の要件であり、Kong 自身の introspection 用認証には直接適用されない。

```yaml
bearer_token_param_type:
  - header
```

アクセストークンを Authorization ヘッダーからのみ受け付ける設定だ。クエリパラメータや POST ボディでのトークン送信を拒否する。FAPI 2.0 は RFC 6750 §5.3 の要求に従い、トークンの URL 露出を禁止しているため、ヘッダー限定にしている。

```yaml
proof_of_possession_dpop: strict
```

DPoP 検証を厳格モードで有効にする設定だ。`strict` を指定すると、`Authorization: DPoP <token>` 形式のリクエストには必ず `DPoP:` ヘッダーが要求される。Kong は以下を検証する：

1. DPoP Proof JWT の署名を Proof ヘッダー内の公開鍵（`jwk`）で検証する
2. その公開鍵の JWK Thumbprint を計算し、アクセストークンの `cnf.jkt` と一致するか確認する
3. Proof の `ath` がアクセストークンの SHA-256 ハッシュと一致するか確認する
4. `htm`・`htu` が実際のリクエストのメソッド・URL と一致するか確認する

これが FAPI 2.0 Security Profile の sender-constrained token 要件を Kong が満たすための中心的な設定だ。

```yaml
consumer_claim:
  - preferred_username
consumer_by:
  - username
```

introspection レスポンスの `preferred_username` クレームを使って Kong の Consumer を特定する設定だ。アクセストークンのユーザー名（`alice`・`bob` 等）と Kong の Consumer レコードを紐付ける。Consumer の特定はできるが、グループ未所属を理由に自動的に拒否されるわけではない。Consumer Group によるアクセス制御を強制するには ACL プラグインなどの追加設定が別途必要だ。

#### Consumer とグループ

```yaml
consumers:
  - username: alice
    groups:
      - name: fapi2-users
  - username: bob
    groups:
      - name: fapi2-users
  - username: charlie   # グループなし
```

alice・bob は `fapi2-users` Consumer Group に属しており、charlie はグループ未所属だ。ただし Consumer Group の定義だけではアクセスは制御されない。グループ所属を理由に拒否するには ACL プラグイン等を追加する必要がある。この `deck/rs.yaml` にはその設定が含まれていないため、現状の構成では charlie が 401 になるとは限らない。将来的にグループベースの認可を追加する場合の土台として Consumer Group を定義している。

---

### Kong Gateway（deck/rp.yaml）

検証 2 で Kong を FAPI 2.0 RP として動作させるための設定。`deck/rs.yaml` との大きな違いは、**Kong がトークンを検証する側ではなく、トークンを取得しに行く側** になる点である。よって `auth_methods` が `authorization_code` + `session` になり、PAR/JAR/private_key_jwt が「Kong 自身が発行・送出する」役割で設定される（JARM・DPoP は Kong プラグインの制約により採用していない、詳細は [検証 2（Kong = RP）の補足](#検証-2kong--rpの補足)）。

#### auth_methods と redirect_uri

```yaml
auth_methods:
  - authorization_code
  - session
redirect_uri:
  - http://localhost:8000/protected
```

- `authorization_code`: 未認証リクエストが来たら Keycloak へ redirect して OIDC 認可コードフローを起動する
- `session`: コールバック後は Cookie のセッションで認可状態を保持する
- `redirect_uri`: Keycloak 側 `kong-rp-client` の `redirectUris` と完全一致させる必要がある

検証 1 の `auth_methods: [introspection]` とは対照的で、検証 1 では「外部から渡されたトークンを introspection で検証する」のに対し、検証 2 では「Kong 自身が認可コードフローを完走してトークンを取得し、後続リクエストはセッション Cookie で認可する」モデルになる。

#### private_key_jwt 認証

```yaml
client_auth:
  - private_key_jwt
client_alg:
  - PS256
client_jwk:
  - kty: RSA
    alg: PS256
    kid: kong-rp-key-1
    n: "..."
    e: AQAB
    d: "..."   # 秘密成分
    # ... p, q, dp, dq, qi
```

`client_auth: private_key_jwt` で FAPI 2.0 が要求する強いクライアント認証方式を選択。`client_jwk` には秘密鍵（`d`, `p`, `q`, `dp`, `dq`, `qi` を含む完全な JWK）を投入する。Kong は PAR・トークンエンドポイントへのリクエスト時に、この秘密鍵で署名した client assertion JWT を `client_assertion` パラメータに乗せる。Keycloak 側は同じクライアントの公開鍵（`jwks.string`）で検証する。

#### PAR / JAR / PKCE

```yaml
require_pushed_authorization_requests: true
require_proof_key_for_code_exchange: true
require_signed_request_object: true
```

- `require_pushed_authorization_requests: true` — 認可リクエストを必ず PAR エンドポイント経由で送る
- `require_proof_key_for_code_exchange: true` — PKCE を必須化（S256 のみ）
- `require_signed_request_object: true` — PAR リクエストに JAR（署名済み Request Object）を含める

これで Security Profile の **PAR + PKCE + private_key_jwt** と Message Signing の **signed authorization requests option（JAR）** をカバーする。

`response_mode: query.jwt`（JARM）と `proof_of_possession_dpop: strict`（DPoP）は本検証では設定していない。理由は「[検証 2（Kong = RP）の補足](#検証-2kong--rpの補足)」を参照。

#### 内部 URL と公開 URL の混在

```yaml
issuer: ${{ env "DECK_ISSUER" }}            # 公開 URL（iss クレーム照合用）
using_pseudo_issuer: true                    # Discovery を抑止
pushed_authorization_request_endpoint: http://keycloak:8080/.../par/request   # 内部 URL
token_endpoint: http://keycloak:8080/.../token                                 # 内部 URL
jwks_uri: http://keycloak:8080/.../certs                                       # 内部 URL
authorization_endpoint: http://keycloak.localhost:9080/.../auth                # 公開 URL（ブラウザ宛）
end_session_endpoint: http://keycloak.localhost:9080/.../logout                # 公開 URL（ブラウザ宛）
```

検証 1 と同じ Docker ネットワーク事情（`KC_HOSTNAME=keycloak.localhost:9080` で発行される `iss` と、Kong コンテナから到達可能な `keycloak:8080` の不一致）への対処である。RP モードでは加えて、**ブラウザに渡す URL は公開 URL でなければならない** ため `authorization_endpoint` と `end_session_endpoint` だけは `keycloak.localhost:9080` を使う。

#### セッション設定

```yaml
session_storage: cookie
session_cookie_name: kong_rp_session
session_cookie_http_only: true
session_cookie_same_site: Lax
session_secret: change-me-in-production-...
session_absolute_timeout: 3600
```

`cookie` ストレージは Cookie 自体に暗号化したセッション情報を載せる方式で、Kong に外部依存（Redis 等）が不要。`session_secret` で署名・暗号化するため、本番では十分にエントロピーのある秘密値に差し替えること。HA / 複数 DP 構成では `session_storage: redis` 等への切り替えを検討する。

#### Backend へのユーザー情報伝達

```yaml
upstream_headers_claims:
  - sub
  - preferred_username
  - groups
upstream_headers_names:
  - x-userinfo-sub
  - x-userinfo-username
  - x-userinfo-groups
```

トークンから取り出したクレームを HTTP ヘッダーで Backend に渡す。Backend（httpbin）は OAuth/OIDC を一切意識せず、これらヘッダーの内容を信頼すればよい。**ただし Backend は必ず Kong 経由でアクセスされる前提を担保すること**（直接公開すると `x-userinfo-*` を偽装されるリスクがある）。

---

### Kong Gateway（deck/rp-mtls.yaml）

検証 3 で Kong を RP として動作させ、Keycloak と **mTLS で相互認証** するための設定。`deck/rp.yaml` との違いは「クライアント認証が `private_key_jwt` から `tls_client_auth` に変わり、すべてのバックチャネルが HTTPS（mTLS）になる」点である。

#### Certificate エンティティ

```yaml
certificates:
  - id: ce451e1b-9c1e-4184-bc22-3e001336e8ed
    cert: |
      -----BEGIN CERTIFICATE-----
      <Kong RP のクライアント証明書 PEM>
    key: |
      -----BEGIN PRIVATE KEY-----
      <対応する秘密鍵 PEM>
```

Kong は **Certificate エンティティ** に登録した cert+key を mTLS 接続時のクライアント証明書として提示する。`tls_client_auth_cert_id` でこのエントリを UUID で参照する。

> Kong の Admin API は `id` に **UUID v4** を要求する（任意の文字列を `id` に書くと `expected a valid UUID` エラーになる）。本リポジトリでは固定 UUID を埋め込んでおり、`tls_client_auth_cert_id` で同じ UUID を参照している。
>
> **`ca_certificates` エンティティは本検証では不要**（`deck/rp-mtls.yaml` には記載していない）。`openid-connect` プラグインは `ca_certificates` を直接参照せず、Keycloak サーバー証明書の検証は **`tls_client_auth_ssl_verify: true` + Kong プロセスレベルの `KONG_LUA_SSL_TRUSTED_CERTIFICATE`（docker-compose.yaml で指定する CA PEM）** で行われる。Kong を RS としても兼ねて `proof_of_possession_mtls: strict` でクライアント証明書バインドトークンを検証する構成に拡張するなど、別プラグインが CA エンティティを参照するケースが出てきた段階で改めて追加すればよい。

#### tls_client_auth でのクライアント認証

```yaml
client_auth:
  - tls_client_auth
tls_client_auth_cert_id: ce451e1b-9c1e-4184-bc22-3e001336e8ed
tls_client_auth_ssl_verify: true
```

`tls_client_auth_cert_id` は配列ではなく **文字列** を渡す（プラグインスキーマが string を要求する）。`tls_client_auth_ssl_verify: true` で Keycloak のサーバー証明書を検証し、検証元 CA は Kong プロセス側の `KONG_LUA_SSL_TRUSTED_CERTIFICATE` で読み込ませている（後述）。

#### HTTPS+mTLS エンドポイントへの接続

```yaml
pushed_authorization_request_endpoint: https://keycloak.localhost:9443/.../par/request
token_endpoint: https://keycloak.localhost:9443/.../token
jwks_endpoint: http://keycloak.localhost:9080/.../certs
authorization_endpoint: http://keycloak.localhost:9080/.../auth
```

Keycloak は HTTPS+mTLS で受け付けるエンドポイント（`mtls_endpoint_aliases`）を別途公開しており、**PAR と Token エンドポイントだけ HTTPS（9443）に切り替える** のがポイント。`authorization_endpoint` は依然としてブラウザ向けなので HTTP のまま。`jwks_endpoint` も mTLS 不要で HTTP で取得できる（ただし HTTPS でもよい）。

#### Kong コンテナ側の TLS 信頼設定

`docker-compose.yaml`:

```yaml
kong:
  volumes:
    - ./tls:/etc/kong/tls:ro
  environment:
    KONG_LUA_SSL_TRUSTED_CERTIFICATE: /etc/kong/tls/ca-cert.pem
```

Kong プラグインから外部 HTTPS を呼ぶとき、**Lua の cosocket TLS は OS のシステム CA ストアではなく `lua_ssl_trusted_certificate` で指定された PEM ファイルを参照する**。本検証ではローカル CA がそれに当たるので、CA 証明書をマウントして環境変数で指定している。これがないと `unable to verify the first certificate` で接続が落ちる。

---

### Keycloak（fapi2-realm.json）

#### Realm レベルの設定

```json
"accessTokenLifespan": 300
```

アクセストークンの有効期限を 300 秒（5分）に設定している。FAPI 2.0 Security Profile は短命なトークンを推奨しており（SHOULD）、長期有効なトークンが盗まれたときのリスクを下げる。

```json
"attributes": {
  "parRequestUriLifespan": "600"
}
```

PAR で発行された `request_uri` の有効期限を 600 秒（10分）に設定している。手動検証でブラウザ操作に時間がかかることを考慮して長めにしているが、FAPI 2.0 Security Profile Final は `expires_in` を 600 秒未満で発行するよう AS に求めており、この値はその上限に当たる。本番環境では短くすることが望ましい。

#### fapi2-test-client の設定

このクライアントは PAR・PKCE・DPoP の挙動を確認するためのテストクライアントとして設定されている。`private_key_jwt` 認証・JAR・JARM は設定しておらず、FAPI 2.0 Final の完全準拠構成ではない。

```json
"require.pushed.authorization.requests": "true"
```

このクライアントへの認可リクエストはすべて PAR 経由でなければならないと Keycloak に強制させる設定だ。`request_uri` を使わない通常の `/authorize` リクエストは Keycloak が拒否する。FAPI 2.0 Security Profile §5.2.2 の必須要件に対応する。

```json
"pkce.code.challenge.method": "S256"
```

PKCE の `code_challenge_method` を `S256` に固定する。`plain` を使ったリクエストは拒否される。FAPI 2.0 は S256 のみを許可している（RFC 7636 の `plain` は禁止）。

```json
"dpop.bound.access.tokens": "true"
```

このクライアントが取得するアクセストークンを必ず DPoP バインドにする設定だ。トークンリクエストに `DPoP:` ヘッダーがなければ Keycloak はエラーを返す。発行されたトークンには `cnf.jkt`（公開鍵の JWK Thumbprint）が埋め込まれ、sender-constrained token になる。

```json
"access.token.signed.response.alg": "PS256",
"id.token.signed.response.alg": "PS256"
```

アクセストークンおよび ID Token の署名アルゴリズムを PS256 に固定する。FAPI 2.0 Security Profile は JWT の署名に PS256・ES256・EdDSA のみを許可しており、RS256 は禁止されている。

```json
"publicClient": false
```

confidential client として設定する。Public client（モバイルアプリ等）はクライアントシークレットを安全に保管できないため、FAPI 2.0 は confidential client または public client ＋ PKCE を要求する。本環境は confidential client として `client_secret_post` 認証を使っているが、FAPI 2.0 本来の要件は `private_key_jwt` または mTLS を要求する。

```json
"directAccessGrantsEnabled": false
```

Resource Owner Password Credentials グラント（`grant_type=password`）を無効にする。FAPI 2.0 はこのグラントタイプを明示的に禁止している。ユーザーの資格情報をクライアントが直接受け取るフローは FAPI 2.0 が前提とする脅威モデル（クライアントを信頼しない）に反する。

#### kong クライアントの設定

このクライアントは Kong Gateway が introspection を行うためだけに使う。

```json
"standardFlowEnabled": false,
"implicitFlowEnabled": false,
"directAccessGrantsEnabled": false
```

認可コードフロー・Implicit フロー・Resource Owner Password Credentials をすべて無効にしている。Kong は introspection のみを行うクライアントであり、エンドユーザー向けのフローは一切不要なため、攻撃対象面を最小化する。

```json
"serviceAccountsEnabled": true
```

Client Credentials グラントを有効にする。introspection エンドポイントへのアクセスに必要なサービスアカウントを Keycloak 内に作成するためのフラグだ。

#### kong-rp-client の設定（検証 2 用）

検証 2 で Kong が RP として Keycloak と OIDC 認可コードフローを行うためのクライアント定義。Kong 自身を **FAPI 2.0 Confidential Client** として登録するための設定が並ぶ。

```json
"clientAuthenticatorType": "client-jwt"
```

`private_key_jwt` 認証を使うことを明示する。Keycloak の用語では Signed JWT 方式と呼ばれ、これに切り替えると `secret` ではなく公開鍵での検証になる。

```json
"attributes": {
  "use.jwks.string": "true",
  "jwks.string": "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"PS256\",\"kid\":\"kong-rp-key-1\",\"n\":\"...\",\"e\":\"AQAB\"}]}"
}
```

Kong（RP）の **公開鍵** を Keycloak に登録する。Kong が PAR・トークンエンドポイントへ送る client assertion JWT の署名を、Keycloak はこの公開鍵で検証する。`use.jwks.string` を `true` にすることで、URL ではなくインライン JSON 文字列で公開鍵を渡せる（PoC・自己完結 realm-import 向け）。本番では `use.jwks.url: true` + `jwks.url` で Kong 側が公開する JWKS エンドポイントを参照させる方が運用しやすい。

```json
"token.endpoint.auth.signing.alg": "PS256",
"request.object.signature.alg": "PS256",
"request.object.required": "request",
"authorization.signed.response.alg": "PS256",
"access.token.signed.response.alg": "PS256",
"id.token.signed.response.alg": "PS256"
```

各種 JWT の署名アルゴリズムを **PS256 で統一** する。FAPI 2.0 は RS256 を禁じており、PS256 / ES256 / EdDSA のみが許容される。

- `token.endpoint.auth.signing.alg`: client assertion（private_key_jwt）の署名アルゴリズム
- `request.object.signature.alg`: JAR の署名アルゴリズム
- `request.object.required: "request"`: 認可リクエストには必ず Request Object を含めることを要求（JAR を必須化）
- `authorization.signed.response.alg`: JARM の署名アルゴリズム（これがあると認可レスポンスを署名付き JWT で返す）
- `access.token.signed.response.alg`: アクセストークン JWT の署名アルゴリズム
- `id.token.signed.response.alg`: ID トークンの署名アルゴリズム

```json
"require.pushed.authorization.requests": "true",
"pkce.code.challenge.method": "S256"
```

PAR を必須化（このクライアントへの認可リクエストは `request_uri` 経由でなければ受け付けない）、PKCE は S256 のみを Keycloak に強制させる。Kong（RP）が誤ってこれらを省略した場合、Keycloak は明確にエラーを返す（FAPI 2.0 強制を AS 側でも担保）。

> `dpop.bound.access.tokens=true` は本来 FAPI 2.0 Security Profile の必須要件だが、Kong の openid-connect プラグインが RP として DPoP Proof JWT を生成できないため、本検証では Keycloak 側でも DPoP 必須化を外している。詳細は「[検証 2（Kong = RP）の補足](#検証-2kong--rpの補足)」参照。

```json
"redirectUris": [
  "http://localhost:8000/*",
  "http://127.0.0.1:8000/*"
]
```

Kong の callback URL を登録する。`deck/rp.yaml` の `redirect_uri: http://localhost:8000/protected` がこの範囲にマッチする。本番では具体的な URL のみを列挙してワイルドカードを避けることが推奨される。

#### kong-rp-mtls-client の設定（検証 3 用）

検証 3 で Kong が **mTLS で認証** されるためのクライアント定義。`kong-rp-client` との違いはクライアント認証方式と sender-constrained 設定だけで、PAR/PKCE/JAR のフラグは共通している。

```json
"clientAuthenticatorType": "client-x509"
```

`private_key_jwt` ではなく **X.509 クライアント証明書** で認証する。Keycloak は `tls_client_auth` 接続で受け取った証明書の Subject DN をクライアント設定の `x509.subjectdn`（または regex パターン）と突き合わせて認証する。

```json
"attributes": {
  "x509.subjectdn": ".*CN=kong-rp-mtls-client.*",
  "x509.allow.regex.pattern.comparison": "true"
}
```

Subject DN を **正規表現** で照合するモードに切り替えている（厳密一致は OpenSSL と Java の DN 表現差で外しやすいため、PoC では regex の方が運用しやすい）。本番運用では `false`（厳密一致）に戻して RFC 2253 形式の DN を完全一致で書く方が望ましい。

```json
"tls.client.certificate.bound.access.tokens": "true"
```

このクライアントが取得したアクセストークンに **`cnf.x5t#S256` クレーム** を埋め込ませる。これが mTLS 方式の sender-constrained token の本体で、トークンの正当な保有者（同じクライアント証明書を提示できる者）以外は使用できなくなる。検証 3 のスクリプトはこのクレームを introspection レスポンスから取り出し、Kong のクライアント証明書 thumbprint と一致するかを比較している。

その他の attributes（`require.pushed.authorization.requests`・`pkce.code.challenge.method: S256`・`request.object.signature.alg: PS256`・`access.token.signed.response.alg: PS256` 等）は `kong-rp-client` と同じである。

#### Realm 全体の HTTPS / mTLS 設定（docker-compose.yaml 側）

Keycloak の HTTPS リスナと mTLS 受け入れは realm JSON ではなく `docker-compose.yaml` の環境変数で制御している。

```yaml
KC_HTTPS_PORT: 9443
KC_HTTPS_CERTIFICATE_FILE: /opt/keycloak/conf/tls/keycloak-cert.pem
KC_HTTPS_CERTIFICATE_KEY_FILE: /opt/keycloak/conf/tls/keycloak-key.pem
KC_TRUSTSTORE_PATHS: /opt/keycloak/conf/tls/ca-cert.pem
KC_HTTPS_CLIENT_AUTH: request
```

- `KC_HTTPS_PORT: 9443` — HTTPS リスナを 9443 に追加（HTTP の 9080 と並走）
- `KC_HTTPS_CERTIFICATE_FILE` / `KC_HTTPS_CERTIFICATE_KEY_FILE` — サーバー証明書 / 秘密鍵（`tls/keycloak-{cert,key}.pem`）
- `KC_TRUSTSTORE_PATHS` — Keycloak 26 で導入された **PEM 形式トラストストア**。指定したファイル / ディレクトリ配下の証明書をクライアント認証の検証用 CA として読み込む（古い `KC_HTTPS_TRUST_STORE_FILE` の PKCS12 ベースは PoC では `Empty reply from server` で動かなかったため、この方式に切り替えている）
- `KC_HTTPS_CLIENT_AUTH: request` — クライアント証明書を **要求はするが必須ではない**（必須にすると HTTPS 全体が mTLS を強制してしまうため、特定エンドポイント単位での mTLS 必須化を Realm 内で行う構成になる）。Keycloak は `tls.client.certificate.bound.access.tokens=true` のクライアントに対して **`mtls_endpoint_aliases`** を Discovery ドキュメントに公開し、RP 側はそちらの HTTPS エンドポイントへ mTLS で接続する流れ

#### Protocol Mapper（groups クレーム）

```json
{
  "name": "groups",
  "protocolMapper": "oidc-group-membership-mapper",
  "config": {
    "access.token.claim": "true",
    "introspection.token.claim": "true",
    "claim.name": "groups"
  }
}
```

ユーザーが所属する Keycloak グループ名をアクセストークンと introspection レスポンスの `groups` クレームとして出力するマッパーだ。`introspection.token.claim: true` が重要で、これがないと Kong が introspection で受け取るレスポンスに `groups` が含まれず、Consumer Group による認可制御が機能しない。

---

## 付録 - 検証中に判明した注意点

検証 1〜3 を実装する過程で踏んだ落とし穴と、本リポジトリの設定値が「なぜそう書いてあるのか」をまとめる。同種の検証環境を構築する場合、ここに挙げる項目は最初に押さえておくと再現で詰まりにくい。

### 共通：Docker / Keycloak のホスト周り

#### Docker Desktop のメモリ割り当て

Keycloak（v26.1.5）+ Kong + Postgres × 2 + httpbin を同時に起動すると、Docker Desktop のデフォルト 4GB ではメモリ不足で Keycloak が OOM 落ちすることがある。検証中も実際に Keycloak が起動途中で止まる事象が発生した。**6GB 以上を目安に割り当てを増やす**こと。

#### Keycloak の内部 / 外部 URL の統一

`docker-compose.yaml` で `KC_HTTP_PORT: 9080` を設定し、`ports: 9080:9080` とマッピングしている。これは **コンテナ内部から見た Keycloak の URL とブラウザから見た Keycloak の URL を完全に揃える** ためで、FAPI 2.0 RP モード（検証 2 / 3）では特に重要だ。

- もし内部ポート（例：8080）と外部ポート（9080）が違うと、Kong が `private_key_jwt` を生成するときの `aud` が `http://keycloak:8080/...` になる一方、Keycloak は `http://keycloak.localhost:9080/...` を期待する。**`aud` mismatch でクライアント認証が失敗する**。
- 同様に、ブラウザがアクセスする `iss` クレーム（`http://keycloak.localhost:9080`）と Kong から見た発行者を揃えないと、Kong が ID トークン検証で issuer 不一致エラーを出す。
- `KC_HOSTNAME_BACKCHANNEL_DYNAMIC: "true"` を併用することで、Kong が `keycloak.localhost` というネットワークエイリアスでアクセスしても Keycloak が正しく応答するようになる。

検証 1（Kong = RS）の旧構成では `using_pseudo_issuer: true` + `introspection_endpoint` 直書きでこの URL 不一致を回避していたが、検証 2 以降の RP モードでは `aud` 一致が必須なので、URL 統一の方が筋が良い。

### 検証 1（Kong = RS）で踏んだ注意点

#### Python `requests` の `.localhost` Cookie 問題

Python の `requests` ライブラリは **`.localhost` サブドメインへの Cookie を自動送信しない**。`scripts/dpop_e2e_verify.py` の認可コード取得ステップで Keycloak のセッション Cookie が送られず、ログインフォームが期待通り遷移しない事象が発生した。

回避策として、`session.cookies` を手動で文字列化し `Cookie:` ヘッダーへ明示的に渡している。

```python
def cookie_header(jar):
    return "; ".join(f"{c.name}={c.value}" for c in jar)

resp = requests.get(url, headers={"Cookie": cookie_header(session.cookies)}, ...)
```

これは検証 2・3 のスクリプトでも同じ理由で必要となる。

#### charlie の認可テストは「期待通り 401」とは限らない

step 12 で fapi2-users グループに所属しない charlie のトークンで Kong にアクセスする手順を載せているが、現状の `deck/rs.yaml` には ACL プラグインが入っていない。**つまり charlie でも 200 が返る可能性がある**。グループ認可を厳密にテストしたい場合は ACL プラグイン or Consumer Group 制御を別途追加する必要がある。本検証では「FAPI 2.0 の必須要件ではない」として最小構成にとどめている。

### 検証 2（Kong = RP）で踏んだ注意点

#### YAML 1.1 の boolean 暗黙変換（`n:` が `false` になる）

`deck/rp.yaml` の `client_jwk` には JWK の RSA 公開鍵パラメータ（`n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`）が並ぶ。**YAML 1.1 仕様ではキー名 `n` は `false` の別名としてパースされる**ため、クォートしないと `client_jwk` のフィールド名が `false: "..."` になり Kong に拒否される。

回避策：1 文字キーをすべて `"..."` でクォートする。

```yaml
client_jwk:
  - kty: RSA
    "n": "kdSGm..."
    "e": "AQAB"
    "d": "..."
    "p": "..."
    "q": "..."
```

#### Kong プラグイン側のキー名は `jwks_endpoint`

Kong `openid-connect` プラグインで JWKS URI を渡すキー名は **`jwks_uri` ではなく `jwks_endpoint`** である。RFC / Discovery 仕様の慣習名と異なるので注意。

#### DPoP の RP 側生成は未対応

Kong `openid-connect` プラグインは **DPoP の検証（RS 用途）はサポートするが、RP として token endpoint へ DPoP Proof JWT を生成する機能はない**。Keycloak で `dpop.bound.access.tokens=true` にすると、Kong の token request が `invalid_dpop_proof` で失敗する。

このため検証 2 では Keycloak 側の DPoP 要件を外している。**FAPI 2.0 で必須の sender-constrained token は別パス（mTLS、＝検証 3）で実現する** という設計判断につながった。

#### JARM（`response_mode: query.jwt`）も Kong RP では未到達

`deck/rp.yaml` で `response_mode: query.jwt` を指定すると、Kong がコールバック時の JARM JWT を認識せず認可フローを最初からやり直す挙動となった。検証 2 では plain `code` 受信としている。Keycloak 側の JARM サポートそのものは確認できているので、これは Kong プラグイン側の制約。

#### `proof_of_possession_auth_methods_validation: false` が必要なケース

DPoP を実際に使う構成では、authorization_code フローと組み合わせると schema violation（DPoP は bearer/introspection/session のみ許可される）が出る。これを回避するには `proof_of_possession_auth_methods_validation: false` を併記する必要がある。検証 2 では DPoP を使わないので明示していないが、DPoP RP が動くようになったら必要となる項目。

### 検証 3（Kong = RP × mTLS）で踏んだ注意点

#### Kong Admin API は `id` フィールドに UUID v4 を要求する

`deck/rp-mtls.yaml` で Certificate / CACertificate エンティティを定義するとき、`id` に任意の文字列（例：`kong-rp-mtls-cert`）を入れると **`expected a valid UUID`** で deck sync が失敗する。UUID v4（例：`8b1c8a5e-...`）を生成して使う必要がある。

```yaml
certificates:
  - id: 8b1c8a5e-4d2f-4e3a-9b8c-1f2e3d4a5b6c   # 任意の UUID v4
    cert: |
      -----BEGIN CERTIFICATE-----
      ...
```

#### `tls_client_auth_cert_id` は文字列（配列ではない）

Kong プラグインの一部では `*_cert_id` 系フィールドが配列を取るが、`openid-connect` プラグインの `tls_client_auth_cert_id` は **単一の文字列** を取る。配列で渡すとスキーマエラーになる。

```yaml
config:
  client_auth:
    - tls_client_auth
  tls_client_auth_cert_id: 8b1c8a5e-4d2f-4e3a-9b8c-1f2e3d4a5b6c   # 文字列で渡す
```

#### Keycloak 26 の PKCS12 トラストストア（`KC_HTTPS_TRUST_STORE_FILE`）は PoC で動かなかった

最初は PKCS12（`.p12`）形式のトラストストアを `KC_HTTPS_TRUST_STORE_FILE` で渡していたが、Kong 側から HTTPS 接続したときに **`Empty reply from server`** が返り、TLS handshake が成立しなかった。Keycloak 26 で導入された **`KC_TRUSTSTORE_PATHS`**（PEM ファイル / ディレクトリを直接指定）に切り替えると正常動作した。

```yaml
KC_TRUSTSTORE_PATHS: /opt/keycloak/conf/tls/ca-cert.pem
```

#### Kong の Lua cosocket は OS 信頼ストアを参照しない

Kong コンテナ内から Keycloak の HTTPS（自己署名 CA で発行）に接続するとき、OS 側の `/etc/ssl/certs` に CA を置いただけでは Kong は信頼してくれない。**Kong が使う Lua cosocket は `KONG_LUA_SSL_TRUSTED_CERTIFICATE` で明示指定された PEM のみを信頼する**。

```yaml
KONG_LUA_SSL_TRUSTED_CERTIFICATE: /etc/kong/tls/ca-cert.pem
```

これを忘れると `unable to verify the first certificate` で token request が止まる。

#### `x509.subjectdn` の厳密一致は外しやすい

Keycloak の `x509.subjectdn` 設定で OpenSSL 表現の DN（`CN=kong-rp-mtls-client,O=...`）をそのまま入れても、Keycloak 内部の Java 表現と微妙に異なり一致しないことがある。**正規表現マッチに切り替える**方が PoC では運用しやすい。

```json
"x509.subjectdn": ".*CN=kong-rp-mtls-client.*",
"x509.allow.regex.pattern.comparison": "true"
```

#### コンテナ初回起動直後の JWKS キャッシュタイミング

Keycloak が起動時に新しいシグニング鍵を生成し、その直後に Kong がメタデータをフェッチしてしまうと、Kong の JWKS キャッシュが古い鍵セットを掴むことがある。`scripts/rp_mtls_e2e_verify.py` 実行時に **`suitable jwk was not found`** エラーが出る場合は、`docker compose restart kong` で Kong を再起動するとキャッシュが綺麗になり解消する。

これは Keycloak 起動 → Kong 起動の順序を保証していない docker-compose 構成での副作用。本格運用では `depends_on` + healthcheck と JWKS の TTL 設定で吸収する。

---

## 付録 - FAPI 認定（Conformance Certification）の取得方法

FAPI の Conformance Certification を実際に取得する場合の手順・費用・運用面の取り扱いを参考としてまとめる。本リポジトリの読者の多くは「[既製品を採用する立場](#立場別conformance-test-との関わり方)」または「PoC・社内検証目的」に該当するため自分でテストを回す必要はないが、製品ベンダーや独自実装する金融機関側の動きを理解しておくと、調達基準の作成や認定済み製品の見極めに役立つ。

### 認定の方式：self-certification

OpenID Foundation の認定は **self-certification** 方式で運営されている。

- **実装者自身がテストスイートを実行し**、結果を OIDF に提出して「自社のこの deployment はこの conformance profile に適合する」と公式に宣言する形式
- **第三者監査（外部 auditor）は不要**
- 認定情報には **実施日** が刻まれる（**有効期限なし**、ただし「Final 仕様での認定」と「Implementer's Draft での認定」は別エントリ扱い。仕様の Final 改訂時には実装者が自主的に再認定するのが慣習）

### テスト環境

公式オンラインプラットフォーム **<https://www.certification.openid.net/>** にログインし（Google または GitLab アカウント）、テストハーネスから自分の AS / RP に対して各テストを実行する。

Conformance Suite 自体は OSS（[gitlab.com/openid/conformance-suite](https://gitlab.com/openid/conformance-suite)）として公開されており self-host も可能だが、**正式な認定提出ではオンライン版を使うのが標準**である。

### 取得手順（OP の場合）

1. オンラインのテストハーネスでプロファイルを選択（FAPI 2.0 OP Security Profile + 必要な Message Signing option 等）
2. テスト用クライアントを登録（DCR 非対応な AS の場合は手動で 3 個登録）
3. 各テストを実行し、結果が `PASSED` / `REVIEW` / `WARNING` / `SKIPPED` のいずれかになることを確認（`FAILED` が残っていると認定不可）
4. **Certification Submission Form** にテストプランの URL とともに結果を提出
5. OIDF 側でレビューが行われ、問題なければ **公式 Implementations 一覧** に掲載される

RP 認定の場合は OP / RP の役割が逆になるが、流れ自体は同じである。

### 費用（per new deployment）

| 種別 | OIDF メンバー | 非メンバー |
| --- | --- | --- |
| OpenID Connect | $700 | $3,500 |
| **FAPI 1 / FAPI 2** | **$1,000** | **$5,000** |
| FAPI-CIBA | $1,000 | $5,000 |

- **同一暦年内** に同じ deployment で複数プロファイルを認定する場合は **追加費用なし**（例：FAPI 2.0 Security Profile を取得した後、同じ年に Message Signing option を追加するのは無料）
- **OP（AS）と RP は別請求**
- 年次更新費の明示的な記載はなく、再認定するかどうかは実装者の判断に委ねられている

外部監査が要らない self-certification 方式のため、**金額面では数千ドル規模で済み、認定取得そのもののハードルは比較的低い**。実態としては「仕様準拠の実装を作り込む側」のコストが本体である。

### 認定の単位（再掲）

[FAPI 2.0 の対応状況](#fapi-20-の対応状況) で触れた通り、認定は **「組織 × 実装（deployment）」単位** で付与される。

- **製品ベンダー**（Authlete, Inc など）が自社製品で認定を取得するケース
- **エンドユーザー企業**（金融機関など）が自社カスタム IdP / 自社デプロイメントで認定を取得するケース

の両方が公式 Implementations 一覧に並ぶ。**ある製品が認定を取得していても、その製品を採用した別企業のデプロイメントには認定が伝播しない**。Open Banking エコシステム参加など、自社デプロイメントとしての認定が必要なケースでは、認定済み製品をベースにしたうえで自社で別途認定を取り直す必要がある。

### エコシステム認定との関係

OIDF 自体の認定とは別に、Open Banking 系のエコシステム（英国 OBIE、ブラジル Open Finance、豪 CDR、米 FDX 等）が **OIDF 認定の上に独自要件を被せた認定プログラム** を運営しているケースがある。

- エコシステム参加要件として **「OIDF の FAPI 認定取得済み」が前提条件** に組み込まれていることが多い
- そのうえで、エコシステム固有の profile（例：ConnectID、CBUAE 等）に対する認定が追加で必要となる
- 公式 Implementations 一覧の profile 列にも、これらエコシステム別 profile が並んでいる

つまり実装者から見ると、**「FAPI 2.0 Security Profile / Message Signing の認定 → エコシステム認定」という二段構え**で取得することになる。

### 関連リソース

- [OpenID Certification ホーム](https://openid.net/certification/)
- [認定費用（Fees）](https://openid.net/certification/fees/)
- [Certification FAQ](https://openid.net/certification/faq/)
- [How to Certify Your Implementation](https://openid.net/certification/how-to-certify-your-implementation/)
- [Conformance Test Platform（オンライン）](https://www.certification.openid.net/)
- [Conformance Suite（OSS）](https://gitlab.com/openid/conformance-suite)

