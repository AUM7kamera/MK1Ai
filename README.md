# MK1Ai

## 利用ガイド

この文書は、リポジトリ内の `airgap_ai_defender.py` を主な実行対象として、初期設定、起動、システム構成、ローカル学習、運用上の注意を説明します。`airgap_ai_defender_6.py` は別の簡易版です。両者の機能やオプションは同一ではありません。

## 重要な注意

- このプログラムはネットワーク監視と OS の隔離操作を行う実験的な防御プロトタイプです。誤検知や設定ミスで通信が切断される可能性があり、実環境での防御性能や安全性は保証されていません。
- まず使い捨ての Linux 仮想マシンで試してください。業務端末、サーバー、リモート接続中の端末では実行しないでください。
- 標準の Dry-Run は脅威検知時のネットワーク遮断コマンドを実行しないモードです。しかし、起動時の `boot_time_auto_hardening()` は別に呼び出され、root で実行すると sysctl やプロセス上限を変更します。Dry-Run でもシステム設定への変更があり得ます。
- `--no-dry-run` を指定すると、検知時にネットワークインターフェース停止やファイアウォール変更を実行します。ネットワークや SSH が切断され、手動復旧が必要になる場合があります。挙動を確認していない状態で指定しないでください。
- Python からのパケット取得には Linux の `AF_PACKET` raw socket と適切な権限が必要です。OS によっては利用できず、このガイドの手順は Linux を前提とします。

## 初期設定

### 1. Python 環境を用意する

Python 3.10 以降の 64-bit Linux 環境を用意します。作業ディレクトリは `~/MK1 Ai` です。ディレクトリ名に空白があるため、シェルでは次のようにエスケープして移動します（`cd ~/MK1 Ai` の実行形です）。

```bash
cd ~/MK1\ Ai
python3 -m venv .venv-mk1
```

通常版は起動時に `torch`、`psutil`、`cryptography` の有無を確認し、不足していれば現在の Python (`sys.executable`) から pip で導入を試みます。PyTorch はCPU版wheel indexを追加して取得します。インストールにはネットワーク接続と書き込み可能なPython環境が必要です。仮想環境を使うと、システムPythonを汚さずに導入できます。

PyTorchが `Failed to initialize NumPy: No module named 'numpy'` を警告する場合、NumPyがそのPython環境にありません。この警告は通常の推論には致命的ではありません。PyTorchとNumPyの相互変換が必要な場合、または警告を解消する場合は、実行に使う同じ環境へNumPyをインストールしてください。

オフライン環境やインストール失敗時は警告を出し、PyTorch/psutilのstubへ移行します。AI推論やパケット監視など一部機能は利用できません。`cryptography` が使えない場合はMemoryManager自体は起動しますが、平文を保存しないためディスクへのデータ退避は無効になります。必要な機能を利用するには、ネットワークが使える環境で一度起動するか、あらかじめ仮想環境へ依存をインストールしてください。

### 2. ネットワークインターフェースを確認する

監視対象のインターフェース名を確認します。

```bash
ip -br link
```

`eth0` はコード上の既定値の例です。実際の環境に存在する名前を使ってください。監視対象が見つからない場合は、仮想マシンのネットワークアダプター設定も確認します。

### 3. モデルの読み込みを設定する

通常版は `--local-dir` の中にある `cloud_base_model.pth` を読み込みます。既定値は `./ai_data/cloud_base_model.pth` です。モデルファイルが存在するだけでは読み込まれず、期待する SHA-256 ハッシュが必要です。ハッシュの期待値は環境変数 `AIRGAP_MODEL_HASH` または `EXPECTED_MODEL_HASH` から取得されます。通常版では `.sha256` サイドカーファイルは期待値として使われません。

信頼できる入手元からモデルを取得した場合は、その入手元が提示したハッシュと照合してください。ローカルファイルから自分で計算したハッシュは、以降のファイル変更検出には使えますが、モデルの出所や品質を証明するものではありません。

```bash
sha256sum ai_data/cloud_base_model.pth
```

確認した信頼済みハッシュを起動時に渡す例:

```bash
sudo env AIRGAP_MODEL_HASH="<確認済みのSHA-256>" \
  .venv-mk1/bin/python airgap_ai_defender.py --interface <監視インターフェース>
```

開発・テスト時は `--ignore-model-hash` を指定すると、ハッシュ照合を省略してモデルのロードを試みます。state_dictの構造検証は引き続き行いますが、ハッシュによるファイル真正性の確認は行いません。信頼できないモデルには使わず、本番運用では信頼済みのハッシュを設定してください。

VS Code などの開発環境では、RSIモードのDry-Runとローカルのデータ保存先を明示して起動できます。`--ram-limit` はMemoryManagerの監視基準であり、OSがプロセスを指定量に制限する設定ではありません。

```bash
COLAB_RSI_ENDPOINT="https://<your-authenticated-endpoint>/rsi" \
  python3 airgap_ai_defender.py --mode RSI --ram-limit 1500 --local-dir ./ai_data --ignore-model-hash
```

`ai_data/config.json` があれば、起動時に引数の初期値として自動読み込みします。明示したCLI引数が設定値より優先されます。例:

```json
{
  "interface": "eth0",
  "ram_limit": 1500,
  "drive_id": "100FIfMbB-0kR2bg2NXl-O1k-Lilz-j_G",
  "colab_endpoint": "https://<your-authenticated-endpoint>/rsi",
  "ignore_model_hash": false,
  "compact_log": true,
  "mode": "RSI"
}
```

`./run.sh` はColab URLを尋ね、前回値がある場合はプロンプトに表示します。空のままEnterを押すと前回値を保持し、新しいURLを入力すると更新します。設定は一時ファイル経由で原子的に `ai_data/config.json` へ保存してから、RSI/1500MB/compact-log設定で起動します。URL入力時にCtrl+CまたはCtrl+Dを押すと、設定を変更せず終了します。`--compact-log` は通常のINFO/WARNINGを抑え、RAM・swap・脅威スコア・Colab状態を1行で更新します。エラーと高スコアの警告は通常ログとして表示します。

この例は Dry-Run です。root 権限は raw socket の利用や起動時ハードニングのために使われます。既知の旧形式（共有層 `10→32→16`、Head A `16→1`）は、出力を保つ形で現在のモデル構造へ自動変換して読み込みます。それ以外の形式、破損したファイル、未設定または不一致のハッシュは安全のためロードを拒否し、未学習状態で起動します。起動ログで `旧形式チェックポイントを現行モデル構造へ互換変換します` またはロード結果を確認してください。

### 4. 最初は Dry-Run で起動する

```bash
sudo env AIRGAP_MODEL_HASH="<確認済みのSHA-256>" \
  .venv-mk1/bin/python airgap_ai_defender.py \
  --interface <監視インターフェース> \
  --local-dir ./ai_data
```

Dry-Run は既定で有効です。停止するには `Ctrl+C` を押します。終了時は特権ワーカーへ共有停止イベントと終了キューを送り、権限降格後の親プロセスから `terminate()` しない形で回収します。キャプチャ用swapは専用のOS一時ディレクトリに作られ、終了時に削除されます。`--local-dir` は実行ユーザーが書き込めるよう、sudo起動前に作成・所有権を確認してください。主なオプションは次のとおりです。

| オプション | 既定値 | 説明 |
| --- | --- | --- |
| `--interface` | `eth0` | 監視インターフェース |
| `--local-dir` | `./ai_data` | モデル、入力データ、厳選データ、作業領域の保存先 |
| `--update-interval` | `300` 秒 | ローカル入力データを再確認する間隔 |
| `--max-memory-mb`, `--ram-limit` | `500` MB | MemoryManager の監視基準値。OS がプロセスのメモリをこの量に制限する設定ではありません |
| `--validation-only` | 無効 | 小規模データ変換と Head B 学習を検証して終了し、パケット監視は起動しません |
| `--max-samples` | `32` | 検証モードで処理する最大サンプル数 |
| `--ignore-model-hash` | 無効 | 開発・テスト用にモデルのSHA-256照合を省略します。信頼できるモデルに限って使用してください |
| `--compact-log` | 無効 | 通常ログを抑え、1秒ごとの1行ステータスを表示します。設定ファイルでは `compact_log` で指定できます |
| `--rsi`, `--mode RSI` | 無効 | RSI学習指示をColabエンドポイントへ非同期送信 |
| `--no-dry-run` | 無効 | 指定すると検知時の実遮断を許可します。ネットワーク断の危険があります |

RSI連携には、Colabノートブックで起動するHTTPS受信エンドポイントを設定します。[Colab連携ノートブック](colab_training.ipynb) は選別済みの10次元特徴量だけを受け取り、Head BをGPUで追加学習してGoogle DriveへモデルとSHA-256を保存します。公開APIにはBearer認証が必須です。ノートブックが表示する `COLAB_RSI_ENDPOINT` と同じトークンを `COLAB_RSI_TOKEN` に設定してください。

このリポジトリのノートブックは空いているloopback portを選び、`cloudflared` で公開して `https://<random>.trycloudflare.com/rsi` を表示します。Colabの出力がLocalTunnel (`*.loca.lt`) やport `5000` を示す場合は、別のノートブックまたは古いランタイムが動いています。設定URLを取り違えないよう、Colab runtimeを再起動してこのリポジトリのnotebookを上から順に実行してください。認証確認では、tokenなしの `POST /rsi` が `401` になることが期待値です。tokenなしの空JSONが `200` になるendpointには、tokenや学習データを送らないでください。

```bash
export COLAB_RSI_ENDPOINT="https://<your-authenticated-endpoint>/rsi"
export COLAB_RSI_TOKEN="<endpoint-token>"
python airgap_ai_defender.py --rsi --ram-limit 1500
```

モデル同期では `--mode RSI` 起動時に `/model.sha256` と `/model` をHTTPSで定期取得します。URLはRSI endpointの `/rsi` をそれぞれ `/model.sha256` と `/model` に置き換えて自動構成します。別ホストやパスを使う場合は `ai_data/config.json` に `model_url` と `model_hash_url` を指定できます。`model_sync_interval` は秒単位（最小30秒）、`model_sync_token` は任意のBearer tokenです。SHA-256とモデル構造の検証に通らないファイルは配置せず、成功時のみ一時ファイルから原子的に置換します。上記の既知の旧形式はロード時に現行構造へ変換されますが、ハッシュ照合は引き続き必須です。実行中はメイン推論ループで新しい重みを適用します。

ローカルから送るのは `curated/curated_data.jsonl` の正常な数値特徴量（最大2048件）だけです。生パケットや通信内容は送信しません。APIはデータをキューへ入れてすぐに受理応答を返し、GPU学習はColab側で非同期に実行します。

RSI endpointへ送るのはタスク名、選別済み特徴量、学習設定、送信時刻だけです。モデルのstate_dictや生パケット、通信内容、学習データのファイル名・容量は送信しません。HTTPS以外の外部URLは拒否し、接続失敗時も通常の監視と既存の小バッチ学習を継続します。`--validation-only`ではエンドポイント未設定時に送信をシミュレートし、最大`--max-samples`件で終了します。

通常起動でも `COLAB_RSI_ENDPOINT` が未設定またはsudoへ引き継がれていない場合、RSI送信はシミュレーションになります。ログに `未設定のため送信をシミュレーション` と出る場合は、endpointを設定し、`sudo --preserve-env=COLAB_RSI_ENDPOINT,COLAB_RSI_TOKEN` で起動してください。

RSIモードでは`--no-dry-run`を同時指定してもDry-Runを維持し、脅威検知を遮断アクションへ昇格させません。検知結果自体は捨てず、監査用WARNINGを最大30秒に1回記録します。プロセス監査では `code`、`code-server`、`node`、`python3` 等の名前だけで免除せず、親プロセスに不審な兆候がなく、接続先がloopbackまたはHTTPSの443番ポートに限られる場合だけリスクを下げます。この扱いはパケット検査の許可リストではなく、通常通信は引き続き検査され、Head Bの正常学習判定にも進みます。

## 学習モードの初期設定と動作確認

ここでいうRSIはColabへ選別済み特徴量を送り、Head Bを追加学習する仕組みです。報酬や方策を使う一般的な強化学習ではありません。学習結果の性能向上も保証されません。

### 通常学習

通常学習はローカルデータまたはGoogle Driveの教材をHead Bへ適合させます。入力JSONLは1行1レコードで、`features` に10個以上の数値が必要です。通常起動のデータ更新にはDrive IDが必要ですが、ローカル検証では空のDrive IDを指定すると外部取得をスキップできます。

設定ファイルの例 `ai_data/config.normal.json`:

```json
{
  "interface": "eth0",
  "drive_id": "<Google-Drive-folder-id>",
  "ram_limit": 1500,
  "compact_log": true,
  "mode": "normal"
}
```

学習用データの例:

```jsonl
{"features": [0.2, 0.1, 1, 1, 0, 0, 1, 0, 0.18, 0.3]}
```

誤検知を減らすための確認済みフィードバックは `ai_data/curated/reviewed_feedback.jsonl` に1行1件で保存します。`label=0` は人が確認した正常通信、`label=1` は人が確認した脅威です。各レコードには正規化済み10次元 `features` が必要です。自動判定結果をそのまま脅威ラベルにせず、必ず人が確認してください。通常学習はこのファイルを起動時に読み込み、Head Bの正常度を正常例では1、脅威例では0へ学習します。

```jsonl
{"features": [0.2, 0.1, 1, 1, 0, 0, 1, 0, 0.18, 0.3], "label": 0}
{"features": [0.9, 0.8, 1, 1, 1, 0, 0, 1, 0.7, 0.9], "label": 1}
```

フィードバックは確認済みデータとして扱うため、ファイルを編集した後に通常モードを再起動してください。少数データだけでは精度を判断できません。RSIでHead Bが両クラスを学習すると、高い正常度が得られた場合にソフトAIスコアのみ最大25%抑制します。DPI、ブラックリスト、パース異常などの確定的な判定はこの補正で解除しません。誤検知率・見逃し率の改善は実データで評価する必要があります。

まず一時データで、外部アクセスなしに実際のHead B学習を確認します。Python環境の準備後、リポジトリのルートで実行してください。

```bash
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/normal/gdrive_raw"
printf '%s\n' \
  '{"features": [0.2, 0.1, 1, 1, 0, 0, 1, 0, 0.18, 0.3]}' \
  '{"features": [0.3, 0.2, 1, 0, 0, 1, 0, 0, 0.12, 0.4]}' \
  > "$TEST_DIR/normal/gdrive_raw/smoke.jsonl"
.venv-mk1/bin/python airgap_ai_defender.py \
  --config "$TEST_DIR/no-config.json" --mode normal --drive-id "" \
  --local-dir "$TEST_DIR/normal" --validation-only --max-samples 2
```

成功時は終了コード `0` と `Head B のオンライン適合学習を 2 件で完了しました` のログを確認します。`--validation-only` はパケット監視を起動しません。実際の教材をDriveから確認するときは、`--drive-id ""` を設定ファイルのDrive IDまたは実際のIDに置き換えてください。通常起動はデータ更新ワーカーがバックグラウンドで学習キューへデータを送ります。

### RSI学習

1. `colab_training.ipynb` をGoogle Colabで開き、上から順に実行してDriveアクセスを許可します。ノートブックが表示するBearer tokenは秘密情報として扱い、公開リポジトリへ保存しないでください。
2. ノートブック末尾で起動するHTTPS tunnelを維持し、表示された `/rsi` endpointをローカル側へ設定します。`COLAB_RSI_TOKEN` にはノートブックが発行したtokenを設定します。
3. 以下の設定ファイル例を使います。tokenをファイルに保存する場合は、ファイルを共有・コミットせず、読み取り権限を制限してください。

```json
{
  "interface": "eth0",
  "ram_limit": 1500,
  "compact_log": true,
  "mode": "RSI",
  "colab_endpoint": "https://<tunnel-host>/rsi"
}
```

まずendpoint未設定でRSIの送信分岐とローカル学習を確認します。RSI検証はDriveを取得せず、既存の `curated/curated_data.jsonl` を使います。endpoint未設定なら送信はシミュレーションされます。

```bash
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir -p "$TEST_DIR/rsi/curated"
printf '%s\n' \
  '{"features": [0.2, 0.1, 1, 1, 0, 0, 1, 0, 0.18, 0.3]}' \
  '{"features": [0.3, 0.2, 1, 0, 0, 1, 0, 0, 0.12, 0.4]}' \
  > "$TEST_DIR/rsi/curated/curated_data.jsonl"
env -u COLAB_RSI_ENDPOINT -u COLAB_RSI_TOKEN \
  .venv-mk1/bin/python airgap_ai_defender.py \
  --config "$TEST_DIR/no-config.json" --mode RSI \
  --local-dir "$TEST_DIR/rsi" --validation-only --max-samples 2
```

Colabへ実データを送る場合は、`reviewed_feedback.jsonl` に正常(label=0)と脅威(label=1)の両方を記録し、endpointとtokenを設定します。RSIは両クラスが揃わないと要求を送信せず、Colab APIも片側だけの要求を拒否します。成功ログの `Colab endpointが学習指示を受理しました` はキューへの受理を示すだけです。Colab側で `Fine-tuned Head B ...` と `Saved SHA-256` が出た後、通常起動中のクライアントが次回同期時（既定300秒間隔）にハッシュ検証済みモデルを取得・反映したことも確認してください。旧形式のローカル適応チェックポイントはラベル極性が逆のため無視されます。ローカル検証コマンドは送信失敗時もローカル学習へフォールバックするため、終了コード `0` だけではColab受理や精度向上の確認になりません。

### 常時起動

検証に成功した後、監視インターフェース名を `ip -br link` で確認して常時起動します。既定でDry-Runですが、root起動では起動時ハードニングが別途実行されます。使い捨てLinux VMでのみ試し、`--no-dry-run` は指定しないでください。

通常モード:

```bash
sudo .venv-mk1/bin/python airgap_ai_defender.py \
  --config ai_data/config.normal.json --mode normal \
  --interface <監視インターフェース> --local-dir ./ai_data
```

RSIモード:

```bash
export COLAB_RSI_ENDPOINT="https://<tunnel-host>/rsi"
read -rsp "Colab Bearer token: " COLAB_RSI_TOKEN
printf '\n'
export COLAB_RSI_TOKEN
sudo --preserve-env=COLAB_RSI_ENDPOINT,COLAB_RSI_TOKEN \
  .venv-mk1/bin/python airgap_ai_defender.py \
  --config ai_data/config.rsi.json --mode RSI \
  --interface <監視インターフェース> --local-dir ./ai_data
```

`sudo --preserve-env` が許可されない環境では、管理者ポリシーに従って秘密情報を安全に渡してください。トンネルURLとColab runtimeは一時的な場合があるため、再接続時は新しいURL/tokenを設定します。RSI起動はDry-Runを強制し、Colabの受理後も学習完了は非同期です。

## システム構成と処理の流れ

通常版は単一の Python プロセスを中心に、パケット取得、脅威判定、ローカルデータ処理をスレッドや補助プロセスに分けて実行します。

1. **環境確認と起動処理**: OS、NIC、利用可能なコマンドや権限を調べます。root で起動した場合、ネットワーク関連 sysctl などのブート時ハードニングを試みます。
2. **モデル**: PyTorch の共有全結合層（入力10次元から64、32、16次元）と3つの出力ヘッドを使います。Head A は異常度、Head B は端末における正常通信との適合度、Head C はメモリ退避の判断材料を出力します。
3. **パケット監視**: Linux raw socket でパケットを受信し、パケット長、到着間隔、IP/TCP/UDP の種別、TCP フラグ、送信元ポート、メモリ使用率などを特徴量にします。追加の DPI・統計・プロセス監査も実施します。
4. **判定と隔離**: 検知ロジックが異常を判断した場合、Dry-Run ではコマンドを記録し、実遮断モードではインターフェースやファイアウォール等を操作します。誤検知でも通信を失う可能性があります。
5. **ローカルデータ更新**: 起動時に `--drive-id` のフォルダ一覧を取得し、サイズを確認できるJSON/JSONL/CSVのうち最大4ファイル（各8 MiB、合計32 MiBまで）を `ai_data/gdrive_raw/` 以下へ直接保存します。既存ファイル、サイズ不明のファイル、上限超過ファイル、アーカイブは取得せず、展開もしません。その後ローカル入力を逐次処理し、条件に合うデータを `ai_data/curated/curated_data.jsonl` に追加して学習キューに送ります。
6. **メモリ管理・補助処理**: RAM 使用量の監視、バッファの一時退避、自己保護監視や Moving Target Defense の補助処理を実行します。

`airgap_ai_defender_6.py` は別実装です。既定では `./cloud_base_model.pth` を参照し、環境プロファイル、ハードニング、メモリ確認などを一度実行して終了します。通常版の継続的なパケット監視・データ更新処理と同じ機能を提供するものではありません。

## ローカル学習の仕組み

このプロジェクトの学習は、モデルをゼロから作る大規模な再学習ではなく、主に端末固有の通信を Head B に適応させる処理です。

- 通常監視では Head B が正常と判定した通信の特徴量を一時バッファに集め、100件単位でバックグラウンド学習キューに送ります。
- ローカル教材は `ai_data/gdrive_raw/` に置きます。JSON配列、JSONL、CSVをストリーミングで読み、100件ずつ処理します。JSON/JSONL の各レコードは10個以上の数値を持つ `features` 配列が必要で、学習用には先頭10個だけを使います。64KiBを超えるJSONレコードやJSONL行は読み飛ばします。例:

```json
{"features": [0.2, 0.1, 1, 1, 0, 0, 1, 0, 0.18, 0.3]}
```

- データはモデルで厳選された後、Head B の学習に使われます。`_train_queue` は最大10バッチを保持し、満杯時は更新側が空きができるまで待ちます。入力バッチ・待機キューが有限なので大きな教材の全件をRAMへ展開しません。ただし、500MBはMemoryManagerの監視基準であり、プロセス全体の厳密なRSS上限ではありません。
- ローカル学習では Head B 以外の重みを凍結し、学習バッチごとにHead Bの重みを `ai_data/local_adaptation.pth` へ原子的に保存します。SHA-256サイドカー `local_adaptation.pth.sha256` も同じ場所へ作成し、次回起動時に検証してクラウド基盤モデルのHead Bへ適用します。Head Aと共有層はローカル適応チェックポイントでは上書きしません。保存に失敗した場合はログに警告し、学習自体は続行します。
- データが少ない、形式が不正、モデルのハッシュ検証やロードに失敗する場合は、想定した適応が行われないことがあります。学習ログと保存データを確認してください。

## 学習時間と必要スペック

リポジトリにベンチマーク結果、正式な最低要件、データ件数あたりの学習時間はありません。以下は動作確認を始めるための**参考目安**であり、保証値ではありません。

| 項目 | 開始時の参考目安 | 補足 |
| --- | --- | --- |
| OS | 64-bit Linux | raw socket と隔離コマンドを使う通常版の前提 |
| Python | 3.10 以降 | 型注釈構文などからの目安。PyTorch の対応版も確認 |
| CPU | 2コア以上 | GPU は必須ではありません。実際のパケット量で負荷は変わります |
| RAM | 4 GB 以上を推奨 | 既定の 500 MB は監視基準値であり、アプリ全体の上限ではありません |
| ディスク | 数 GB の空き領域を確保 | Python/PyTorch 環境、入力データ、ログ、一時ファイルのため。データ量に応じて増やします |

モデルは小規模な全結合ネットワークですが、実際の処理時間は CPU、PyTorch ビルド、パケット頻度、DPI 処理、入力データ件数、ストレージ速度などに左右されます。「推論1ms以下」等のコメントは目標・記述であり、このリポジトリで測定・保証された性能値ではありません。

学習時間の確定値は、実際の端末で同じ件数のデータを使って測定してください。最初は Dry-Run で起動し、ログ、CPU/RAM 使用率、処理件数を確認します。大きな教材を投入する前に、小さな JSONL データで更新サイクルを試してください。

Drive取得からパーサー、Head Bのオンライン適合学習までを小規模に確認する場合は、常駐監視を起動せず次を実行します。`--ram-limit` は監視基準値であり、プロセスの厳密なRSS上限ではありません。

```bash
python airgap_ai_defender.py \
  --drive-id "100FIfMbB-0kR2bg2NXl-O1k-Lilz-j_G" \
  --ram-limit 1500 --validation-only --max-samples 32
```

Driveに接続できない場合は既存の `ai_data/gdrive_raw/` データ、またはそこにデータがなければ `ai_data/curated/curated_data.jsonl` の先頭32件を検証に使います。

## 学習させるメリットとデメリット

| 観点 | 内容 |
| --- | --- |
| メリット | 端末内の通信傾向に合わせた Head B の適応を試せます。ローカル入力だけで動作するため、教材を外部サービスへ送らずに処理できます。 |
| メリット | 学習処理をバックグラウンドキューに送る設計で、通常の判定ループから分離されています。 |
| デメリット | 入力の誤ラベル・偏り・汚染により、正常通信の判定が偏る可能性があります。学習は検知精度向上を保証しません。 |
| デメリット | ローカル適応は主に Head B であり、新しい攻撃に対する Head A の検知能力が自動的に向上する仕組みではありません。 |
| 注意点 | 保存されるのは端末固有のHead B重みです。Head Aの攻撃検知能力を自動的に高めるものではなく、SHA-256は破損検出用でモデルの出所を証明する署名ではありません。 |
| デメリット | 誤検知時の隔離操作は可用性に影響します。Dry-Run でも起動時ハードニングは別途実行されます。 |
| デメリット | 学習・隔離・DPI は本番環境での評価や認証を示すものではありません。既存のファイアウォール、EDR、監視体制の代替として扱わないでください。 |

## トラブルシューティング

- **モデルをロードしない**: `--local-dir` 内に `cloud_base_model.pth` があるか、環境変数 `AIRGAP_MODEL_HASH` または `EXPECTED_MODEL_HASH` が正しいか、モデル構造がこのコードと合っているかを確認します。
- **raw socket の権限エラー**: Linux で必要な権限があるか、インターフェース名が正しいかを確認します。root 実行は起動時システム設定にも影響するため、使い捨て VM でのみ試してください。
- **データが学習に使われない**: ファイルが `ai_data/gdrive_raw/` 以下にあるか、拡張子が `.json` / `.jsonl` か、各レコードに10個以上の数値を含む `features` があるか、更新ログを確認します。
- **ネットワークが切断された**: Dry-Run でない場合、コンソールに出る復旧コマンドを確認し、ローカルコンソールからインターフェースやネットワークサービスを復旧します。リモート接続だけに頼って実行しないでください。

## テスト

リポジトリのテストを実行するには、仮想環境を有効にしたうえで次を実行します。

```bash
.venv-mk1/bin/python -m unittest discover -s tests -v
```

テストの成功は、特定の補助関数の動作確認です。本番ネットワークでの検知精度、安全性、処理性能を保証するものではありません。
