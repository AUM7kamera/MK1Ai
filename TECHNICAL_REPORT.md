# MK1Ai 技術レポート

- 調査日: 2026-10-09
- 対象: このリポジトリのソースコード、設定テンプレート、依存関係、README、テストコード
- 評価の範囲: 静的な実装確認。実ネットワーク、実機、証明書、暗号モジュールの認証試験は実施していません。

## 1. まとめ

MK1Ai は、ネットワークパケットの監視と異常判定を試みる Python アプリを中心に、C 言語の操作パネル、USB デバイス隔離、暗号化された RSI 学習連携、閲覧専用のリモート画面、脅威イベント表示などを組み合わせた**実験的な防御プロトタイプ**です。

ソフトウェア上には、Dry-Run、ルート確認、鍵の消去要求、メモリ保護、USB スキャン用の隔離ゲストといった安全策があります。一方で、README 自身も検知性能、OS 全体の通信遮断、秘密の完全消去、実運用の安全性を保証していません。既定の Dry-Run は検知後の遮断を試さない設定であり、root 起動時のシステム設定変更など、すべての副作用を無効にするものではありません。

**CNSA 2.0 評価: リポジトリ内の設定・実装は CNSA 2.0 準拠とは判断できません。** AES-256-GCM や TLS の AES-256-GCM-SHA384 など一部に共通する暗号要素はありますが、アプリケーション層と TLS の PQC 鍵交換は ML-KEM-768 であり、CNSA 2.0 の ML-KEM-1024 とは一致しません。また、CNSA 2.0 で指定される ML-DSA-87 の署名を使う構成は確認できません。WireGuard の標準暗号（Curve25519 / ChaCha20-Poly1305）も別の暗号プロファイルです。

これはソースコード上の照合結果であり、NSA による評価、FIPS 140 認証、製品認証、または実通信の適合性試験ではありません。

## 2. システム全体の見取り図

```text
Linux 上の MK1Ai 監視プロセス
  ├─ パケット取得・特徴量化・ルール/モデルによる判定
  ├─ Dry-Run または設定された隔離操作
  ├─ ローカル学習データの処理
  ├─ USB 監視・隔離（Linux の実遮断モードなど条件付き）
  ├─ C/ncurses 操作パネル
  ├─ 暗号化 RSI 通信 ── WireGuard ── Colab の学習/API
  ├─ 読み取り専用画面 ── WireGuard ── Nginx/TLS
  └─ 任意の地図イベント ── localhost WebSocket またはローカル保存
```

**小学生向けに言うと:** 番犬役のプログラムが通信の特徴を見て、怪しいと感じたら「これは危ないかも」と知らせます。操作パネルは番犬の設定をするリモコンです。USB 検査やリモート画面は追加の道具ですが、どれも魔法の盾ではなく、設定や動作環境によって使えないことがあります。

### 主な処理の流れ

1. 起動時に設定、ネットワークインターフェース、モデルファイル、利用できるライブラリなどを確認します。
2. Linux の `AF_PACKET` raw socket でパケットを受け取り、IP/TCP/UDP の情報やペイロードの特徴を調べます。ここでいう特徴は、通信先やサイズなどの観察材料であり、暗号化された通信の中身を常に読めるという意味ではありません。
3. ルールや PyTorch のモデルでリスクを評価します。Dry-Run では脅威判定が実際の遮断操作に直結しないようにします。実遮断を許可した場合は、誤判定で通信を失う可能性があります。
4. 選別されたデータはローカルの JSON/JSONL/CSV 処理や、設定された場合の Head B 適応学習に使われます。RSI 連携は、確認済みの特徴量を外部学習環境へ送る経路です。
5. 任意機能として、USB の監視・スキャン、リモート状態表示、地図イベント、メモリ保護、WireGuard 制御を行います。それぞれに OS 権限・外部サービス・追加パッケージなどの前提があります。

## 3. 技術・ライブラリと役割

| 技術・ライブラリ | 何に使うか | やさしい説明と注意点 |
| --- | --- | --- |
| Python 3 | 監視、データ処理、モデル呼出し、各種サービスの中心 | システムの指揮役です。実ネットワーク監視と隔離は主に Linux 前提です。 |
| PyTorch (`torch`) | 特徴量から複数のスコアを出すニューラルネットワーク、Head B 学習 | たくさんの例から数値の傾向を学ぶ計算道具です。学習したから検知精度が上がるとは限りません。依存がないとスタブへ移行する設計があり、その場合は本物の AI 推論・学習を行いません。 |
| `psutil` | メモリ、プロセス、ネットワーク等の OS 情報取得 | コンピューターの状態を読む温度計のような役目です。stub では実際の状態を測れません。 |
| NumPy | 数値・配列処理や PyTorch との連携 | 数字をまとめて扱う道具です。README では通常推論に必須ではない場合もあると説明されています。 |
| `requests` / `gdown` | HTTPS 要求、Google Drive のデータ取得など | Web サービスや Drive からデータを受け取る道具です。設定・ネットワーク・サービス側の制限に左右されます。 |
| Linux `AF_PACKET` | Ethernet パケットのユーザー空間での取得 | ネットワークの封筒を受け取る入口です。権限が必要で、非 Linux 環境では同じ監視能力を前提にできません。 |
| `cryptography` | AES-GCM、HKDF などの暗号 API | 暗号の部品を呼び出すライブラリです。 |
| `pqcrypto` 1.0.0 | アプリ層 RSI 通信の ML-KEM-768 | 量子計算機にも耐えることを目指す鍵共有方式の実装です。ここで採用されているのは CNSA 2.0 の ML-KEM-1024 ではなく ML-KEM-768 です。 |
| OpenSSL EVP | C の AES-256-GCM、HKDF-SHA-256、乱数、秘密バッファ消去。USB スキャンイメージ署名の検証にも OpenSSL CLI を利用 | 暗号処理の共通基盤です。使っていることだけで FIPS 認証済みとは言えません。 |
| `liboqs` (任意) | C トンネル部品に ML-KEM-768 provider を接続 | インストール時だけ有効になる追加部品です。未導入なら C 側 provider は使えません。実際の RSI クライアント通信は Python 側が担います。 |
| C11、ncurses | ローカル端末で動く操作パネル | 文字画面のメニューを作り、監視・WireGuard・メモリ保護などを操作します。ncurses は画面表示用です。 |
| pthread / Unix domain socket | C パネルと Python 監視プロセスの同期制御 | 同じコンピューター内のプロセス間連絡路です。パネルから暗号送信の停止や鍵消去を依頼します。 |
| WireGuard | 外側の VPN トンネルと経路制御 | ネットワーク上に作る保護された通り道です。標準暗号は Curve25519 と ChaCha20-Poly1305 で、CNSA 2.0 専用暗号スイートではありません。 |
| Nginx + OpenSSL 3.5 以降 (テンプレートで想定) | リモート画面の TLS 1.3 終端 | ブラウザーとの HTTPS の入口です。テンプレートは `TLS_AES_256_GCM_SHA384` と `X25519MLKEM768` を指定します。テンプレートを実環境に適用しなければ、この設定になったとは言えません。 |
| `webauthn` 2.8.0 | リモート画面の Passkey 認証 | 端末の認証器と公開鍵暗号で本人確認する仕組みです。生体認証のみを強制するものではありません。 |
| SQLite | リモート画面の認証情報・状態管理 | 小さなデータベースです。状態ファイルには権限設定がありますが、運用環境の保護も必要です。 |
| Flask | Colab ノートブック内の RSI API | 学習依頼を受け取る Web サーバーの枠組みです。Colab 側で使われます。 |
| Google Colab / Drive、Cloudflare Tunnel | 外部の学習実行環境、モデル保管、Colab API への一時的な公開経路 | MK1Ai の外にあるサービスです。データと通信の保護・利用条件は各サービスと運用設定にも依存します。 |
| QEMU/KVM、ClamAV | USB ストレージを隔離ゲストで読み取り専用スキャン | 怪しい USB を別の使い捨てコンピューターに見立てて調べます。ゲストにネットワークを与えない設定ですが、隔離はホスト・カーネル・QEMU 等に依存します。 |
| JSON / JSONL / CSV、SHA-256 | 設定・学習記録・イベント保存、モデル/イメージのハッシュ照合 | ハッシュはファイルが変わったかを照合する指紋です。信頼できる出所や署名を単独で証明するものではありません。 |
| `unittest`、C テスト、Clang Static Analyzer | 自動テストと C 静的解析 | コードの一部の動きを確かめます。テスト合格だけで実環境の安全性や規格準拠は証明できません。 |

この表は主な外部技術をまとめたものです。`json`、`socket`、`ssl`、`threading`、`subprocess` など Python 標準ライブラリの個別一覧は省略しています。`libsodium` と `libbpf` は任意依存として可用性を確認する記述がありますが、主要な監視・RSI 機能の必須実装としては扱っていません。

## 4. 主な機能

### 4.1 ネットワーク監視と AI スコア

主な実行対象は [airgap_ai_defender.py](./airgap_ai_defender.py) です。パケットを解析して特徴量を作り、モデルや追加の検査ロジックで異常・脅威の可能性を評価します。モデルには複数の出力ヘッドがあり、文書化された設計では Head A は異常スコア、Head B は正常通信への適合、Head C はメモリ管理の判断材料を扱います。

**たとえ:** 監視員が「いつもと違う通信か」「学習した通常パターンに近いか」を点数にします。ただし、点数は確定的な判決ではなく、誤検知も見逃しもあり得ます。リポジトリには本番環境で測った検知率・誤検知率のベンチマークはありません。

`airgap_ai_defender_6.py` は別の簡易版です。通常版と同じ継続監視機能を持つものとして扱わないでください。

### 4.2 隔離と Dry-Run

Dry-Run は、検知時の実遮断操作を避けて判定を試すためのモードです。`--no-dry-run` や C パネルの実遮断操作はネットワークインターフェース等を停止する可能性があります。SSH やリモート接続も切れ、遠隔復旧できなくなる場合があります。

Dry-Run であっても root 起動時のブート時ハードニング等は別処理であり、OS 設定に副作用を与える場合があります。使い捨て Linux 仮想環境での確認が前提です。

### 4.3 ローカル学習と Colab/RSI

通常のローカル適応は主に Head B を更新し、データは有限サイズのキューを通じて処理します。RSI は強化学習ではなく、確認済み特徴量を用いた追加学習として実装されています。ノートブックでは正常・脅威の両方のラベルを要求し、生パケットは受け付けない設計です。

制御可能なクライアント/API の RSI ペイロードは ML-KEM-768 で共有秘密を作り、HKDF-SHA-256 から鍵を導出して AES-256-GCM で暗号化します。公開鍵の SHA-256 pin も検査します。Google Drive/Colab 自体の通信や Google 管理 TLS は別管理であり、このアプリから暗号スイートを指定できません。RSI の「受付」は学習完了を意味せず、Colab 側ログとモデル保存・同期を別に確認する必要があります。

### 4.4 C 操作パネルと暗号トンネル部品

[mk1_panel.c](./mk1_panel.c) は ncurses の対話式パネルを提供します。Python 監視プロセスとは Unix domain socket で連携し、状態表示、USB/地図/トンネル/メモリ保護の切替を扱います。

[mk1_tunnel.c](./mk1_tunnel.c) は OpenSSL EVP を使った AES-256-GCM と HKDF-SHA-256 の C 部品、および ML-KEM-768 provider 接続の仕組みを持ちます。liboqs が導入されている場合は [mk1_tunnel_oqs.c](./mk1_tunnel_oqs.c) が ML-KEM-768 を提供します。これは Python RSI 通信とは別の C パネル用構成要素で、CNSA 2.0 の ML-KEM-1024 ではありません。

### 4.5 USB デバイス隔離

[mk1_usb_guard.py](./mk1_usb_guard.py) は Linux USB の追加イベントを監視し、すべての USB HID を許可リストなしで遮断します。VID/PID/シリアル番号は機器自身が提示し偽装できるため、認証情報として信頼しません。USB ストレージは sysfs unbind でホストから切り離し、署名・ハッシュ確認済みのゲストイメージを QEMU/KVM で起動して、ネットワークなし・読み取り専用で ClamAV スキャンします。検査エラーや脅威の場合は安全側へ倒す制御があります。

これは USB の電源を物理的に切る機能ではありません。イメージ署名の公開鍵・署名アルゴリズム・信頼の起点は運用環境の設定に依存します。Linux の root 権限、KVM/QEMU、適切に署名・準備されたスキャンイメージなどが必要で、README でも実験的機能とされています。

### 4.6 リモート画面と認証

[mk1_remote_dashboard.py](./mk1_remote_dashboard.py) は読み取り専用ダッシュボードと Passkey 認証を実装し、ログイン構成では Gmail OTP と SMS OTP を組み合わせます。サーバー側は loopback に限定し、リモートからの HTTPS は WireGuard アドレスに bind する Nginx 終端を通す構成です。認証・ネットワーク・OTP の設定が不足すれば起動できない設計箇所があります。

**たとえ:** 画面を見せる窓口に、端末の鍵とメール・SMS の確認を組み合わせた入場確認をつけています。ただし、Passkey の端末側確認は指紋とは限らず PIN の場合もあります。また、SMTP/SMS 事業者や外部ネットワークの安全性までアプリが保証するわけではありません。

### 4.7 地図イベント

[mk1_map.py](./mk1_map.py) は `OFF` / `CHROME` / `LOCAL` のモードを持つ非同期イベント配信機能です。Chrome モードでは localhost の WebSocket を使い、Local モードではイベントをローカル保存します。キューとキャッシュに上限があります。地理データのない位置、RSSI 距離、確実に判定できない OS などは推測せず `null` / `unknown` として残します。実座標を割り出す GeoIP 機能ではありません。

### 4.8 プロセスメモリ保護

[mk1_memory_guard.py](./mk1_memory_guard.py) と [mk1_memory_guard.c](./mk1_memory_guard.c) は Linux の ptrace/dump 抑止、core dump 制限、TracerPid の監視、可能な場合の `mlock` / `MADV_DONTDUMP` を実施し、C 側のバッファは `OPENSSL_cleanse` で消去します。

**たとえ:** 秘密のメモを机に置いたままにしにくくし、覗き見や自動撮影を減らす工夫です。暗号ライブラリ内部の複製、Python の不変データ、スワップ、カーネルや root 権限の攻撃者までを消去・防御できる保証ではありません。Linux 専用の実験的保護です。

## 5. CNSA 2.0 基準による評価

### 5.1 判定

**判定: CNSA 2.0 準拠を確認できず、現在のリポジトリ構成は CNSA 2.0 の暗号スイートとして不適合です。**

CNSA 2.0 は単に「AES を使う」「量子耐性をうたうライブラリを入れる」だけの基準ではありません。鍵交換、署名、ハッシュ、対称暗号などの用途別に定められたアルゴリズムと強度を、製品全体の通信・証明書・鍵管理まで含めて確認する必要があります。

| CNSA 2.0 要素 | このリポジトリで確認したもの | 評価 |
| --- | --- | --- |
| AES-256 | RSI の AES-256-GCM、C の AES-256-GCM、Nginx TLS 1.3 cipher suite | AES-256 自体は共通要素。ただし採用されているだけで製品全体の適合性を意味しません。 |
| SHA-384 / SHA-512 系 | Nginx の `TLS_AES_256_GCM_SHA384` では SHA-384 が suite 名に含まれる。アプリ層の HKDF と鍵 pin / ハッシュ確認は SHA-256 | CNSA 2.0 の全用途要件を満たすことは確認できません。アプリ層の処理には SHA-256 が残ります。 |
| ML-KEM-1024 | RSI / C トンネル / Colab API は ML-KEM-768。Nginx group は `X25519MLKEM768` | **不一致**。ML-KEM-768 は標準化された PQC KEM ですが、CNSA 2.0 の ML-KEM-1024 プロファイルとは異なります。 |
| ML-DSA-87 | ソース、依存、Nginx テンプレートに ML-DSA-87 の利用構成を確認できず | **未確認 / 不適合**。TLS 証明書署名や WebAuthn 認証器署名も、実際のアルゴリズム・証明書を調べていません。 |
| LMS / XMSS などのハッシュベース署名 | CNSA 2.0 用途の実装は確認できず。USB ゲストの manifest は署名検証するが、鍵と署名方式は外部設定 | CNSA 2.0 用の署名だと判断できません。 |
| WireGuard の外側暗号 | WireGuard 標準の Curve25519 と ChaCha20-Poly1305 を使用 | CNSA 2.0 の指定アルゴリズムだけで構成されたトンネルとは確認できません。 |

### 5.2 TLS テンプレートの評価

[mk1-remote-nginx.conf.template](./mk1-remote-nginx.conf.template) は TLS 1.3、`TLS_AES_256_GCM_SHA384`、`X25519MLKEM768` を指定します。

- TLS の対称暗号・ハッシュ名に AES-256-GCM / SHA-384 が含まれる点は CNSA 2.0 の要素と共通します。
- 鍵交換 group は ML-KEM-768 を使うハイブリッド構成であり、CNSA 2.0 の ML-KEM-1024 と同一ではありません。
- Nginx 設定ファイルはテンプレートです。実際の Nginx/OpenSSL ビルド、証明書の署名方式、クライアントとのネゴシエーション、適用中の設定を検証していません。
- HTTPS を使う外部サービスの暗号スイート、Google 管理の通信、SMTP/SMS 事業者の接続方式まで、MK1Ai のテンプレートが統一・強制するわけではありません。

### 5.3 CNSA 2.0 適合を主張する前に必要な追加検証

1. CNSA 2.0 の対象範囲（どのプロセス、通信経路、鍵、証明書を適合させるのか）を定義する。
2. ML-KEM-1024、ML-DSA-87、および署名・ハッシュ要件を用途ごとに満たす実装・証明書・運用鍵を確認する。
3. WireGuard、WebAuthn、TLS 証明書、Colab/Drive、SMTP、SMS など、外部境界を含む全経路の適合可否を明示する。
4. 使用する暗号モジュールのバージョン、ビルド設定、FIPS 140 の認証状態を、ベンダー証跡と実環境で確認する。
5. 実通信のハンドシェイク、証明書チェーン、アルゴリズム選択、異常時の fallback の有無を試験し、第三者による適合性評価を行う。

アルゴリズムを置き換えるだけでは足りません。互換性、鍵形式、証明書、API、外部接続先の制御まで含む設計変更と試験が必要です。

## 6. EAL7（Common Criteria）に関する評価

### 6.1 EAL7 の意味

Common Criteria の EAL（Evaluation Assurance Level）は、製品が「絶対安全か」を表す点数ではなく、定められた製品範囲・セキュリティ目標に対して、どの程度の厳密さで設計・実装・証拠を評価するかを表す保証パッケージです。EAL7 は EAL1〜EAL7 のうち最も高い保証レベルで、正式な設計検証と厳密な評価証拠を要求するものです。

**小学生向けに言うと:** EAL7 は「テストをたくさん通した」というシールではありません。設計図、作り方、実際の製品が一致するかを数学的な方法も使って確かめ、決められた製品と使い方について、認定された評価機関が細かく審査する大きな手続きです。それでも、あらゆる使い方・将来の変更・すべての攻撃に対して安全という意味ではありません。

### 6.2 このリポジトリに対する判定

**EAL7 認証・評価済みとは主張できません。** 本リポジトリには Common Criteria の Security Target（ST）、確定した Target of Evaluation（TOE）境界、EAL7 の評価証拠一式、正式な設計検証資料、認定評価機関の評価報告書・認証書を確認できません。通常の単体テストや静的解析の合格だけで EAL7 になるものではありません。

この作業で実施するソースコード点検、セキュリティ関連単体テスト、ネイティブ C テスト、静的解析は、開発上の欠陥を見つけるための**限定的な検証**です。EAL7 適合評価の代替ではなく、認証の保証水準を付与するものでもありません。

### 6.3 今後必要な手順

1. 評価対象の製品バージョンと TOE 境界（OS、C/Python 部品、暗号ライブラリ、Nginx、USB ゲスト、運用鍵を含むか）を固定する。
2. セキュリティ課題、想定脅威、運用環境、信頼境界、要求する保証を記述した ST を作成し、適用可能な Protection Profile と保証パッケージを選定する。
3. EAL7 に必要な形式的仕様・設計・実装対応の証拠、構成管理、開発環境管理、脆弱性分析、試験資料、再現可能なビルド成果物を準備する。
4. Common Criteria 認定スキームの下で、認定された評価機関と認証機関に適用可能性を確認し、正式な評価を受ける。要件や評価コスト、利用可能なスキームは製品と管轄により異なる。
5. 認証された構成と、実際に配布・稼働する構成が一致することを保守・変更管理で継続的に証明する。

### 6.4 この作業でのテスト範囲

ここでいう「セキュリティテスト」は、実行可能なリポジトリ内テスト、C のネイティブテストと Clang 静的解析、およびソースコードレビューを指します。破壊的な遮断操作、外部ネットワークへの攻撃、実システムへの侵入試験は含めません。

### 6.5 コードレビューで見つかった問題と修正

| 重要度 | 対象 | 問題 | 対応 |
| --- | --- | --- | --- |
| MEDIUM | USB HID の識別・許可ポリシー | VID/PID/シリアル番号は USB 機器が提示する偽装可能な値であり、同じ値をまねた機器が登録済み HID として許可される可能性がありました。 | descriptor による HID allowlist と enrollment 機能を削除し、USB HID を登録状態に関係なくすべて unbind する fail-closed 方針へ変更。旧 allowlist ファイルが残っていても読み込みません。 |

この修正は可用性との引き換えです。USB キーボード、マウス等も例外なく遮断され、sysfs unbind が失敗した場合には物理接続を切れません。USB 以外のローカル入力・復旧手段を用意し、使い捨て Linux 環境で実機確認してください。暗号学的に認証できる専用 HID はこのリポジトリでは実装していません。

### 6.6 検証結果

| 検証 | 実行結果 |
| --- | --- |
| セキュリティレビュー | 1 件（MEDIUM、confidence 9/10）を確認し、上記のとおり修正。 |
| USB ポリシーの回帰テスト | `/workspaces/MK1Ai/.venv-mk1/bin/python -m unittest discover -s tests -p 'test_usb_guard.py' -v` — 14 tests passed。旧 allowlist に一致する VID/PID/serial の HID も遮断するテストを追加。 |
| Python 全テスト | `/workspaces/MK1Ai/.venv-mk1/bin/python -m unittest discover -s tests -v` — HID 方針修正後に 182 tests passed。 |
| C ネイティブテスト・静的解析 | `make check` — C ビルド、OpenSSL/AES-GCM、秘密バッファ消去、ptrace 制限等が成功。liboqs がないため ML-KEM-768 C 往復テストは SKIP。 |
| Pylance | `mk1_usb_guard.py` の診断なし。`tests/test_usb_guard.py` に未使用引数の警告が 1 件あり、この修正とは無関係。 |

これらは限定的なソースレビューと自動検証です。物理 USB、KVM パススルー、配備先の udev/自動マウント競合、実ネットワーク、Common Criteria 評価を検証したものではありません。

## 7. 既知の制約と安全な読み方

- 「AI」「エアギャップ」「PQC」「隔離」という名前や機能は、独立評価済みの防御保証を意味しません。Colab、Google Drive、SMTP/SMS などを使う構成は外部通信を伴います。
- Dry-Run は実遮断の試験ではありません。実遮断は通信や SSH を失うおそれがあり、実機に対する自動実験は避けてください。
- SHA-256 照合はファイル変更の検出には役立ちますが、署名鍵や信頼済み配布元を別に確かめなければ真正性の証明になりません。
- `mlock`、ダンプ抑止、鍵バッファ上書きは有用な緩和策ですが、すべてのコピーを消す・盗難を防ぐ保証ではありません。
- `make check` 等の C テストや Python の単体テストが成功しても、実トラフィック上の有効性、誤検知率、パフォーマンス、CNSA 2.0 適合性は証明されません。
- 本レポート作成で確認したテスト範囲を超える実ネットワーク、Colab、配備済み Nginx/OpenSSL の構成は検証していません。

## 8. 主な参照先

### リポジトリ内

- [README.md](./README.md) — 実行方法、機能、制限、運用上の注意
- [airgap_ai_defender.py](./airgap_ai_defender.py) — 主監視プロセス、モデル、データ処理
- [airgap_ai_defender_6.py](./airgap_ai_defender_6.py) — 別実装の簡易版
- [mk1_secure_transport.py](./mk1_secure_transport.py) — WireGuard 経路確認、ML-KEM/AES-GCM RSI transport
- [mk1_tunnel.c](./mk1_tunnel.c) / [mk1_tunnel_oqs.c](./mk1_tunnel_oqs.c) — C 暗号部品と任意 liboqs provider
- [mk1_remote_dashboard.py](./mk1_remote_dashboard.py) / [mk1-remote-nginx.conf.template](./mk1-remote-nginx.conf.template) — リモート画面と TLS テンプレート
- [mk1_usb_guard.py](./mk1_usb_guard.py) — USB ポリシーと隔離スキャン
- [mk1_map.py](./mk1_map.py) — 地図イベント配信・ローカル保存
- [mk1_memory_guard.py](./mk1_memory_guard.py) / [mk1_memory_guard.c](./mk1_memory_guard.c) — Linux メモリ保護
- [colab_training.ipynb](./colab_training.ipynb) — Colab 側 RSI API と Head B 学習
- [Makefile](./Makefile)、[tests/](./tests/) — C のビルド・テスト・静的解析、Python のテスト

### 規格資料

- Common Criteria, [Common Criteria for Information Technology Security Evaluation, Part 3: Security assurance components, Version 3.1 Revision 5](https://www.commoncriteriaportal.org/files/ccfiles/CCPART3V3.1R5.pdf) — EAL 保証コンポーネント
- NSA, [Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) FAQ](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSI_CNSA_2.0_FAQ.PDF) — CNSA 2.0 の公式説明
- NIST, [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM の標準と 512/768/1024 の各パラメータセット
- NIST, [FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA 署名標準
- NIST, [FIPS 197: Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final) — AES 標準
- NIST, [FIPS 180-4: Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) — SHA-2 を含むハッシュ標準
