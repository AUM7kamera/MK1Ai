# MK1Ai

## 利用ガイド

この文書は、リポジトリ内の `airgap_ai_defender.py` を主な実行対象として、初期設定、起動、システム構成、ローカル学習、運用上の注意を説明します。`airgap_ai_defender_6.py` は別の簡易版です。両者の機能やオプションは同一ではありません。

## 重要な注意

- このプログラムはネットワーク監視と OS の隔離操作を行う実験的な防御プロトタイプです。誤検知や設定ミスで通信が切断される可能性があり、実環境での防御性能や安全性は保証されていません。
- まず使い捨ての Linux 仮想マシンで試してください。業務端末、サーバー、リモート接続中の端末では実行しないでください。実遮断は誤検知でもSSHを含む全通信を失わせ、遠隔復旧できなくなる場合があります。
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

For Colab RSI/PQC transport, install the pinned ML-KEM implementation before starting:

```bash
.venv-mk1/bin/python -m pip install -r requirements-secure-transport.txt
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

`--ignore-model-hash` は開発・テスト専用です。モデルファイルのSHA-256真正性確認を省略するため、本番運用では使用しないでください。PyTorchが利用できない状態でこのオプションを有効にした場合、起動を拒否します。

VS Code などの開発環境では、RSIモードのDry-Runとローカルのデータ保存先を明示して起動できます。`--ram-limit` はMemoryManagerの監視基準であり、OSがプロセスを指定量に制限する設定ではありません。

```bash
COLAB_RSI_ENDPOINT="https://<your-authenticated-endpoint>/rsi" \
  python3 airgap_ai_defender.py --mode RSI --ram-limit 1500 --local-dir ./ai_data
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

`management_ports`（整数のリスト）と `management_ips`（文字列のリスト）を `config.json` に記載すると、キルスイッチ発動時に `build_containment_plan` へ自動で渡されます。何も記載がない場合は従来どおり `full_isolation`（全NIC隔離）で、管理経路は保護されません。`management_ports` / `management_ips` を書いた場合は、実行時に `containment_mode` を `management_safe_harbor` に自動的に切り替えます（警告ログを出力）。また、SIGUSR1 による鬼モード(ONI_MODE)の切替は既定で無効です。`--allow-oni-signal` または `"allow_oni_signal": true` を指定した場合のみ有効になります。

`./run.sh` は既定でRSIモードを使い、USB遮断は無効のまま起動します。Colab URLを尋ね、前回値がある場合はプロンプトに表示します。空のままEnterを押すと前回値を保持し、新しいURLを入力すると更新します。`ram_limit`、`mode`、`compact_log` は未設定の場合だけ既定値を保存し、既存の設定値は上書きしません。壊れた `config.json` は上書きせずエラー終了し、`ai_data` は権限 `0700` にします。URL入力時にCtrl+CまたはCtrl+Dを押すと、設定を変更せず終了します。`--compact-log` は通常のINFO/WARNINGを抑え、RAM・swap・脅威スコア・Colab状態を1行で更新します。エラーと高スコアの警告は通常ログとして表示します。

### C言語操作パネル

明示的な起動コマンドを実行したときだけ、C/ncursesのローカル操作パネルが起動します。自動起動やバックグラウンド起動は登録しません。

```bash
bash ./mk1-panel.sh
```

- ChromebookはLinux開発環境 (Crostini) の端末で起動します。macOSはTerminalで起動します。WindowsはWSLとLinuxディストリビューションを用意し、コマンドプロンプトから `mk1-gui.cmd` を実行します (Windowsネイティブ版ではありません)。各環境にCコンパイラ、ncurses、OpenSSL開発ファイルおよび `pkg-config` が必要です。
- ネイティブCのビルドと実行安全性テストは `make check` で実行できます。Linuxのfork子プロセスで `PR_SET_DUMPABLE` によるptrace拒否を試し、OpenSSL初期化/AES-256-GCMと `OPENSSL_cleanse` のゼロ化を検証します。libsodium・libbpf・liboqsは任意依存としてロード/API可用性/初期化を検査し、未導入の場合はSKIPを明示します。liboqs未検出時はパネルをPQC providerなしでビルドします。必須にする場合は `bash ./mk1-panel.sh --require-oqs` を指定してください。liboqsの開発パッケージがある環境ではC側の実ML-KEM-768 keygen/encapsulate/decapsulateとAES-GCM往復も実行します。`make analyze` はClang静的解析を実行します。
- `[1]` は起動前警告に同意した後にDry-Run監視を起動します。Dry-Runは異常を検知しても通信を切断しないため、実際の遮断を提供しません。
- `[3]` は監視開始前に全通信遮断の警告を表示し、続行には `y` と管理者認証が必要です。監視中は検知前の警告待ちやユーザー確認を挟まず、検知後に全ネットワークインターフェースの停止を試行します。停止成功後に操作パネルとリモート画面サーバーを終了します。SSHや遠隔アクセスも切断される可能性があり、遠隔復旧経路は提供しません。誤検知やOSの権限・ファイアウォール・カーネルの制限により、遮断に失敗する場合があります。
- TUIはステータス、脅威イベントログ、RAM/swapメーターを分割表示し、レベル別カラー、対応端末でのマウスショートカット、キーボードガイドを提供します。pthread workerはstatus/logファイルを非同期に読み込み、ncurses描画と入力は単一UIスレッドで行います。テレメトリ更新間隔は約500msで、操作時の認証・設定ダイアログやOSコマンド実行が非同期になる保証ではありません。
- `[4]` でNIC、RAM監視基準、通常/RSIモード、Colab HTTPS URLを編集できます。`[5]` はNIC一覧、`[6]` はGoogle Driveへ接続しないローカル検証です。監視中は処理パケット/秒、累計、脅威・バックドアリスク、隔離状態、RAM・swapを表示します。設定は `ai_data/panel-config.json` に権限 `0600` で保存し、ログは `ai_data/panel.log` に追記します。
- `[m]` は地図モードを `OFF` → `Chrome` → `Local` の順に切り替えます。監視中は設定ファイルの変更を監視ループが反映し、OFFでは地図ワーカーを起動しません。Chromeモードは `127.0.0.1:9001/map` のWebSocketで、Chrome拡張Originからの読み取り専用接続だけを受け付けます。`MK1_MAP_EXTENSION_ORIGIN=chrome-extension://<拡張ID>` (カンマ区切りで複数可) を設定するとそのOriginだけに固定されます。未設定の場合は警告を出し、ローカルにインストールされた任意の拡張が接続できるため、使用する拡張IDの固定を推奨します。Localモードは外部通信をせず、イベントを `ai_data/map-events.jsonl` に保存します (Raylib描画はこのMVPには含みません)。
- 地図イベントは脅威判定後に上限付きの非同期キューへ投入し、配信・保存は遮断処理と別スレッドで行います。イベントにはグローバルIPのみを含め、GeoIPデータセットがない位置、RSSIがない距離、パケットから確実に判別できないOSは `null` / `unknown` のままです。日本の市区町村や海外の行政区画、実座標を推定する機能ではありません。
- `[7]` は閲覧専用ダッシュボードを起動し、`[8]` は停止します。依存を `.venv-mk1/bin/python -m pip install -r requirements-remote.txt` で導入します。アプリはloopbackにだけHTTP bindし、外部接続はNginxがWireGuard IP上でTLSを終端します。スマートフォンを含むクライアントもWireGuardへ接続しなければ到達できません。
- `[u]` はUSB隔離ポリシーをローカルで切り替えます。Linuxの `[3]` 実遮断モードに限り、別のrootワーカーがUSB ueventを監視します。Dry-Run、RSI、macOS、非root起動ではUSBを遮断しません。リモート画面からこの設定を変更するAPIはありません。
- `[e]` は `MK1_WIREGUARD_INTERFACE` (未設定時 `wg0`) のリンクを `/usr/local/sbin/mk1-wg-link` 専用ラッパー経由で切り替え、PQC/AES-GCM送信ゲートへ設定を通知します。切断はWireGuardリンク上の全通信に影響し、起動は既存インターフェースをupにするだけで `wg-quick` の構成読込は行いません。監視中は0600のUnix domain socketでPython暗号バックエンドへ同期要求し、無効化時にはCの `mk1_secure_key_wipe()` とPython側の鍵破棄を行ってからリンクdownを試みます。RSI送信を再許可する前にアプリがWireGuard peerとIPv4/IPv6デフォルト経路を再検証します。Cの `mk1_tunnel.c` はOpenSSL EVPでAES-256-GCM/HKDF-SHA-256を実装します。liboqs開発パッケージがあれば `mk1_tunnel_oqs.c` が実ML-KEM-768 providerを接続し、なければPQC C providerを利用できません。パネルの実通信は既存の `pqcrypto`/`cryptography` Pythonバックエンドが担い、ダミーPQC実装や平文fallbackはありません。ML-KEM単体は相手認証を提供しないため、公開鍵の真正性と信頼済み配布経路が前提です。CトンネルのHKDF salt/infoはPython RSI実装と異なり、両プロトコルは互換ではありません。鍵wipeはアプリ所有バッファへの措置で、暗号ライブラリ内部・不変オブジェクト・allocator内の全コピーやカーネル内WireGuard秘密鍵まで消去する保証ではありません。リンク状態と暗号化送信ゲートは別々に fail-closed となり、物理NICやOS全体のegress kill-switchを保証しません。
- `[3]` の実遮断モードは `sudo -n` で `airgap_ai_defender.py` と `MK1_PYTHON_BIN` をroot権限で実行します。ユーザーが書き換えられるスクリプトやPythonを昇格実行しないよう、パネルは起動前にそれらのパス(と親ディレクトリ全て)がroot所有かつgroup/other書込不可であることを検証し、満たさなければ起動を拒否します。実遮断を使う場合はリポジトリとvenvをroot所有の場所(例 `/opt/mk1ai`)に配置してください。
- Cパネルの権限昇格では `ip` 全体に `NOPASSWD` を付けないでください。`sudo -n ip` を広く許可すると `ip netns exec` 等で任意のrootコマンドを実行されるおそれがあります。パネルは `/usr/local/sbin/mk1-wg-link` 専用ラッパーを呼びます。これをroot所有・非書込可能で配置し、sudoersにはラッパーだけを許可してください。

```bash
sudo install -o root -g root -m 0755 security/mk1-wg-link /usr/local/sbin/mk1-wg-link
```

sudoersには実行ユーザーに応じて `/usr/local/sbin/mk1-wg-link` だけを登録し、`/usr/sbin/ip` 全体やワイルドカード付きのルールは登録しないでください。ラッパーは `ip link set dev INTERFACE up|down` 以外を実行しません。
- `[a]` はLinuxプロセスメモリ保護を切り替えます。パネルと監視プロセスのダンプ抑止、ptrace制限、TracerPid監視に加え、保護中の暗号セッション鍵への `mlock` / `MADV_DONTDUMP` 適用を試みます。設定ONを監視プロセスへ適用できない場合はFail-Closedで起動を中止します。
- USBスキャンが脅威を返した場合も同じローカルIPCでメイン防衛プロセスへ同期的に鍵消去を要求してから、rootワーカーがiproute2によるNIC遮断を試します。IPC確認に失敗してもNIC遮断は続行します。
- 独自のcBPFフィルター・Netlink Connector ABI組み立て・AF_PACKET用カーネルバイパスは削除しました。パケット検査はユーザー空間で行い、プロセス監視は `psutil` による定期走査です。低遅延XDP/eBPF offloadや `SCHED_FIFO` は実装・保証していません。USB脅威時のNIC停止はroot所有の `iproute2` 実行ファイルに `ip link` netlink操作を依頼し、状態を再照会します。

### Linux USB隔離 (実験的機能)

これはOS上の**論理隔離**であり、USB電源を物理的に切る機能ではありません。USBのsysfs unbindに失敗すれば物理接続は維持されます。また、ソフトウェア設定だけで「軍事レベル」や侵害不能を保証することはできません。専用の電源遮断ハードウェア、Linux/KVM、USBコントローラー、udev/自動マウント構成を含め、実機での検証が必要です。

有効化すると、**すべてのUSB HID機器 (キーボード、マウス等) を許可リストに関係なく拒否**し、USBストレージは未承認として扱います。初回有効化時に接続済みHIDがあればロックアウト警告を出し、既定では有効化を拒否します。既存HIDも一律に切断する運用を明示的に許可する場合に限り、`MK1_USB_BASELINE_ALLOW=1` を設定してください。キーボード等を失っても復旧できるローカル手段を用意してください。VID/PID/シリアル番号は機器自身が提示し偽装できるため、本人確認には使いません。USBストレージはホストのusb-storage/UASドライバーを外してから、USBデバイスをネットワークなしの一時QEMU/KVMゲストへ直接渡し、読み取り専用でマウントしてClamAVスキャンします。スキャン中もHID・未承認機器は直ちに切断し、QEMUスキャンは別ワーカーで行います。QEMU出力には上限があり、超過・nonce不一致・複数判定行はエラーとして扱います。スキャン後はclean判定でもUSBをホストへ自動再認可しません。脅威判定ではUSBの論理切断を試行し、併せてrootワーカーが検証済みiproute2実行ファイル経由で全ネットワークインターフェースの停止を試します。検証鍵・署名・イメージ・QEMU/KVM・スキャン・sysfs操作のいずれかが失敗した場合、USBを未許可として切断します。ゲスト内でファイルシステムを読めない場合もclean扱いにせず、fail-closedにします。

**ホストのマウント競合:** uevent監視はカーネルイベントの非同期通知です。udevルールは一般的なUDisks自動マウントを抑止し、既にマウント済みのUSBブロックデバイスはゲストへ渡さず切断します。しかし、独自の自動マウンター、別の特権プロセス、カーネル/udevのタイミングまで完全に封じるものではありません。使用するLinuxディストリビューションで自動マウントを無効化し、udevルールを配備して試験してください。

1. LinuxホストにQEMU (`qemu-system-x86_64`)、KVM (`/dev/kvm`)、Docker/BuildKit、OpenSSL、`sha256sum`、ClamAVの信頼できる `main.cvd` と `daily.cvd` (または `.cld`) を準備します。Alpine base imageは完全な `sha256` digestで、APK repositoryはTLSを使う固定snapshot URLにしてください。ClamAVデータベースの内容も固定します。GNU cpioのreproducible modeと `gzip -n` を使い、同じ固定入力から同じinitramfsを生成します。
2. ゲストをビルドします。例の `@sha256:<64桁>`、snapshot URL、database path、epochは、運用者が信頼できる値に置き換えてください。

   ```bash
   bash security/usb-scan-guest/build.sh \
     --base-image 'alpine:VERSION@sha256:<64桁のdigest>' \
     --apk-repository 'https://<固定snapshot>/alpine/vVERSION' \
     --clamav-db /path/to/pinned-clamav-db \
     --output /tmp/mk1-usb-scan-guest
   ```

3. 未署名アーティファクトをオフライン署名端末へ移し、オフライン保管するEd25519秘密鍵 (権限 `0600`) で `bash security/usb-scan-guest/sign.sh /secure/offline/signing-key.pem /path/to/mk1-usb-scan-guest` を実行します。署名端末で得た公開鍵は、別の信頼済み経路でホストへ配備してください。ゲストと同じ未信頼転送経路から入手した公開鍵をそのまま信頼してはいけません。
4. root所有の場所へ検証済みアーティファクトを配置し、公開鍵をホストの独立した信頼根として固定します。

   ```bash
   sudo install -d -o root -g root -m 0755 /etc/mk1ai /var/lib/mk1ai/usb-scan-guest
   sudo install -o root -g root -m 0644 /path/to/mk1-usb-scan-guest/mk1-usb-scan-signing.pub /etc/mk1ai/usb-scan-signing.pub
   sudo install -o root -g root -m 0644 /path/to/mk1-usb-scan-guest/vmlinuz /var/lib/mk1ai/usb-scan-guest/vmlinuz
   sudo install -o root -g root -m 0644 /path/to/mk1-usb-scan-guest/initramfs.cpio.gz /var/lib/mk1ai/usb-scan-guest/initramfs.cpio.gz
   sudo install -o root -g root -m 0644 /path/to/mk1-usb-scan-guest/manifest.json /var/lib/mk1ai/usb-scan-guest/manifest.json
   sudo install -o root -g root -m 0644 /path/to/mk1-usb-scan-guest/manifest.sig /var/lib/mk1ai/usb-scan-guest/manifest.sig
   sudo install -D -o root -g root -m 0644 security/udev/99-mk1ai-usb-storage.rules /etc/udev/rules.d/99-mk1ai-usb-storage.rules
   sudo udevadm control --reload-rules
   ```

   画像ディレクトリ、各イメージ、manifest、署名と公開鍵はroot所有かつgroup/world writableでないことが必要です。画像ディレクトリまでの親ディレクトリ連鎖もroot所有かつgroup/otherから書き込めない場所にし、通常サービスユーザー `mk1ai` が書き込める場所の下へ配置しないでください。ホストが検証する公開鍵は `/etc/mk1ai/usb-scan-signing.pub` に固定し、ゲストディレクトリ内の公開鍵を自動信頼しません。
5. Cパネルで `[u]` を有効にしてから `[3]` の実遮断監視を起動します。USBワーカーは監視中も設定変更をポーリングするため、`[u]` 切替を反映します。挿入中の機器も有効化時に検査します。すべてのUSB HID機器は遮断され、登録・許可リストによる例外はありません。リモートダッシュボードは閲覧専用のままで、USB設定・認証・起動・停止を行えません。

KVM/実USBパススルーはCIやコンテナ内の単体テストでは検証されません。配備前に使い捨てLinux機で、HID機器がすべて遮断されること、clean/threat/timeout、署名不一致、改ざん済みイメージ、QEMU/KVM不在、既マウント媒体、iproute2によるNIC停止失敗、ローカル復旧手順を実機検証してください。署名済みゲストはClamAVのスキャン結果を保証せず、未知の脅威、ファームウェア攻撃、BadUSB、ホストカーネルやハイパーバイザーの脆弱性は防げません。

```bash
export MK1_REMOTE_ROLE="login"
export MK1_REMOTE_HOST="127.0.0.1"
export MK1_REMOTE_PORT="8080"
export MK1_WIREGUARD_INTERFACE="wg0"
export MK1_WIREGUARD_BIND_ADDRESS="10.77.0.1"
export MK1_REMOTE_ORIGIN="https://security.example.com:8443"
export MK1_REMOTE_RP_ID="security.example.com"
export MK1_ADMIN_EMAIL="admin@example.com"
export MK1_EMAIL_FROM="security@example.com"
export MK1_SMTP_USERNAME="admin@example.com"
export MK1_SMTP_APP_PASSWORD="<Gmail-app-password>"
export MK1_ADMIN_PHONE="+819012345678"
export MK1_TWILIO_ACCOUNT_SID="<Twilio-account-SID>"
export MK1_TWILIO_AUTH_TOKEN="<Twilio-auth-token>"
export MK1_TWILIO_FROM_NUMBER="+15555550123"
bash ./mk1-panel.sh
```

Passkey登録と本番ログインは別コンテナ・別モードです。登録サーバーでは `MK1_REMOTE_ROLE=enrollment` とし、`https://<RPドメイン>/register` で一度だけPasskeyを登録します。登録専用サービスにはメール/SMS資格情報を渡しません。登録後に生成される `owner_profile.dat` はWebAuthn公開鍵など公開情報だけを含む `0400` ファイルです。Proxmoxホストで本番コンテナを停止し、次の移行スクリプトを実行します:

```bash
sudo bash ./proxmox-transfer-registration.sh 101 100
```

このスクリプトはプロフィール形式を検証して本番コンテナの `/etc/mk1ai/owner_profile.dat` へ移し、本番サービス起動を確認した後に登録コンテナの自動起動を無効化して停止します。本番の環境ファイル `/etc/mk1ai/remote-dashboard.env` は `MK1_REMOTE_ROLE=login`、`MK1_OWNER_PROFILE=/etc/mk1ai/owner_profile.dat` を設定してください。systemdユニットは認証DBの保存先を `MK1_DATA_DIR=/var/lib/mk1ai/dashboard` に固定します。認証DBとカウンターは更新が必要なので、プロフィールの `0400` と異なり専用DBをサービスユーザーだけが書き込める状態で保持します。`0400` はrootからの変更を防ぐものではありません。登録コンテナの通信をファイアウォールでも遮断し、停止後に再起動できない運用にしてください。

本番サインインはPasskeyに加えて、GmailとSMSへ並行送信する別々の6桁コードを両方要求します。メールまたはSMSの送信に失敗した場合はログインできません。メール/SMSは同一端末で閲覧可能な場合があり、暗号学的に独立した物理要素とは限りません。ブラウザー内に追加の2桁コードを表示しても独立要素にならないため、追加MFA因子としては実装していません。成功後の画面/APIは状態・検知アラートの読み取り専用です。設定変更、停止/起動、任意コマンド実行のAPIはありません。セッションは15分無操作または最大2時間で失効し、認証段階が進むたびにIDを再発行します。

このPasskey + SMS OTP + Gmail OTPの3要素認証はHTTPSリモートダッシュボード用です。地図WebSocketはlocalhost上の読み取り専用テレメトリー経路で、リモート公開しないでください。Chromeモードを選んだときだけ `127.0.0.1:9001` をlistenします。
systemdで起動する場合は [mk1-remote-dashboard.service](./mk1-remote-dashboard.service) を両コンテナに配置し、各コンテナの `/etc/mk1ai/remote-dashboard.env` に個別のロール・WireGuardアドレス・URLを設定します。サービスは `mk1ai` 非rootユーザー、`ProtectSystem=strict`、`NoNewPrivileges` で動作します。Pythonアプリはloopbackだけにbindし、NginxのみWireGuardアドレスへbindします。

外部HTTPSは [mk1-remote-nginx.conf.template](./mk1-remote-nginx.conf.template) を実環境用に設定して使います。NginxをOpenSSL 3.5以降で構築し、TLS 1.3の `TLS_AES_256_GCM_SHA384` とハイブリッドPQC鍵交換 `X25519MLKEM768` だけを許可します。対応していないNginx/OpenSSLやクライアントでは接続が成立しません。古い鍵交換へのフォールバックを有効にしないでください。Passkey登録・リモートUIもこのHTTPS終端を通るため、TLSが成立しなければ画面/APIを使用できません。

WireGuardの完全なegress kill switchは各Proxmox/LXCの権限・トポロジーに合わせてファイアウォール側で設定します。[egressルールのテンプレート](./mk1-wireguard-egress.nft.template)は、許可したWireGuard UDP peer宛ての外側パケットと `wg0` 内の通信以外を遮断するための例です。IPv4/IPv6のどちらか一方だけのendpointにも対応するレンダラーを使い、`MK1_ALLOW_DHCP=1` を設定したときだけDHCPv4/v6・NDPの許可ルールを含めます。ARPは別のnftables `arp` output tableで許可します。peer endpoint IP/portとinterface名を確定し、ホスト上で適用前にルールを監査してください。

```bash
MK1_ALLOW_DHCP=1 python3 ./mk1_render_nft.py \
  --interface wg0 --endpoint <peer-IP> --port <peer-UDP-port> \
  --output /etc/nftables.d/mk1ai-egress.nft
```

アプリは起動時にIPv4/IPv6フルトンネルrouteとbind IPを検査し、Gmail/Twilio送信の直前にもrouteを再確認しますが、route検査だけでは競合状態や後日の設定変更を防げません。

例としてテンプレートからNginx設定を作る場合は、プレースホルダーを実環境のVPNアドレスとRPドメインへ置換し、TLS証明書パスも合わせます。その後 `nginx -t` と `openssl list -tls-groups` で設定・hybrid groupを確認し、実際のTLS handshakeでもsuite/groupを検証してください。Nginx/OpenSSLやiPhone側ブラウザーがPQC groupに対応しない場合は接続が失敗します。互換性目的の古典鍵交換fallbackは追加しません。

```bash
sed -e 's/WG_BIND_ADDRESS/10.77.0.1/g' \
    -e 's/RP_DOMAIN/security.example.com/g' \
    mk1-remote-nginx.conf.template \
    > /etc/nginx/conf.d/mk1-remote.conf
nginx -t
```

両コンテナへアプリと仮想環境を配置した後、`mk1ai` ユーザーと状態ディレクトリを準備します。環境ファイルはroot所有 `0600` とし、NginxはコンテナのWireGuard IPにだけbindします。クライアント側もWireGuard peerとして構成し、RPドメインがそのVPN内アドレスへ解決されるようにしてください。

```bash
install -d -o mk1ai -g mk1ai -m 0700 /var/lib/mk1ai /var/lib/mk1ai/dashboard
install -d -o root -g mk1ai -m 0750 /etc/mk1ai
install -o root -g root -m 0600 remote-dashboard.env /etc/mk1ai/remote-dashboard.env
systemctl enable --now mk1-remote-dashboard.service
```

登録用 `/etc/mk1ai/remote-dashboard.env` では `MK1_REMOTE_ROLE=enrollment` とし、SMTP/Twilioの秘密情報は設定しません。登録が成功すると `/var/lib/mk1ai/owner_profile.dat` が作成されます。本番側は `MK1_REMOTE_ROLE=login`、`MK1_DATA_DIR=/var/lib/mk1ai/dashboard`、`MK1_OWNER_PROFILE=/etc/mk1ai/owner_profile.dat` とし、Gmail SMTP/Twilioを設定します。systemdユニットは `MK1_DATA_DIR` を `/var/lib/mk1ai/dashboard` に固定します。両方のコンテナで `MK1_REMOTE_ORIGIN` と `MK1_REMOTE_RP_ID` を一致させてください。移行スクリプトは本番サービスが正常起動したことを確認できなければ登録コンテナを停止しません。

**WebAuthnのUser VerificationはFace ID/指紋を保証しません。** Safari/Chrome/OSは端末PINやパスコード等を代替に選ぶことがあり、サーバーは生体方式とPIN方式を確実に識別できません。TLSとPasskeyは必要ですが、外部公開は使い捨て環境で検証してから行い、管理者のGmail/Twilioアカウント・電話番号も保護してください。エアギャップ後は全NIC停止とともにローカルパネルおよびリモートダッシュボードを停止します。ネットワーク断中にスマートフォンから閲覧できる保証はありません。

Passkey登録・リモートUI・WebAuthn/MFA APIは、WireGuard内のNginx TLS終端を通し、TLS 1.3 `TLS_AES_256_GCM_SHA384` とML-KEM-768 hybrid group `X25519MLKEM768` に限定します。学習APIはこれに加え、制御可能なRSI payloadをML-KEM-768＋AES-256-GCMでアプリケーション暗号化します。Google Drive/Colabのmount・Google API通信はGoogle管理TLSであり、この暗号スイートを指定できません。Gmail SMTP/Twilio APIへの接続はWireGuard route/egress firewallと各事業者TLSを使いますが、各事業者TLS suiteはMK1Aiから固定できず、Twilio以降のSMS通信も事業者・携帯網に依存します。したがって全外部リンクで同一暗号suiteを強制した、あるいは永久に解読不能とは保証しません。

生体方式は強制できず、公開URL・DNS・証明書・SMTP/Twilioの実接続は管理者が構成する必要があります。C UIの複数OS対応は起動環境の対応であり、Pythonの実パケットキャプチャはLinuxの `AF_PACKET` が前提です。Linux以外ではキャプチャがシミュレーション動作となる場合があるため、実ネットワークの監視・隔離機能が動作したとみなさないでください。実環境へ投入する前に、OS別の隔離コマンドを使い捨て環境で個別に検証してください。

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

RSI連携には、Colabノートブックで起動するHTTPS受信エンドポイントを設定します。[Colab連携ノートブック](colab_training.ipynb) は選別済みの10次元特徴量だけを受け取り、Head BをGPUで追加学習してGoogle DriveへモデルとSHA-256を保存します。制御可能なMK1Ai↔Colab API通信では、ML-KEM-768公開鍵のSHA-256 pinning、ML-KEM共有秘密から導出した鍵、AES-256-GCMを使い、認証token・RSI要求/応答・モデルとハッシュをアプリケーション層で暗号化します。tokenはBearer HTTP headerではなく暗号化payloadに含みます。endpoint、token、公開鍵fingerprintのいずれかが不足すれば実送信しません。

WireGuardは各実行環境で利用者が用意・起動し、`wg0` に `0.0.0.0/0` と `::/0` の両方を設定してください。アプリは両方の外向きrouteが `wg0` を使うことを確認し、検証できなければColab/Drive通信を拒否します。ColabノートブックもDrive mount前に同じ確認を行い、`MK1_WIREGUARD_INTERFACE` で別名を指定できます。トンネル設定、peer鍵、秘密鍵は利用者側で安全に管理してください。

Cパネルの `[e]` は管理者確認後に既存WireGuardリンクだけをup/downします。downで通信を遮断しても、wg-quick/systemd設定、ルート、カーネル内の長期秘密鍵を削除する動作ではありません。ユーザー空間の有効なアプリ層鍵はPython transport側とC tunnel側で消去し、以降の暗号送信を拒否します。Python側は可変鍵バッファを上書きし、C側はOpenSSL `OPENSSL_cleanse` を用います。ML-KEM実装や暗号ライブラリの内部コピー、Pythonの不変オブジェクト、スワップ、クラッシュダンプまで物理消去できる保証はありません。リンク操作後もOS firewallのegress kill-switchが必要です。

WireGuardの標準プロトコル自体はCurve25519とChaCha20-Poly1305を使い、AES/PQCへ置き換えることはできません。ここではWireGuardを外側トンネルとして使い、その上に制御可能なMK1Ai↔Colab API向けのML-KEM-768/AES-256-GCM暗号化を重ねます。Google Colab `drive.mount`、Google Drive API、Google/CloudflareのTLS暗号選択は各サービスが管理しており、MK1AiからPQC鍵交換やTLS cipher suiteを強制できません。Drive通信はWireGuard経由に制限しますが、Google管理のTLSは別途維持されます。ルート確認は通信直前の検査であり、VPN切断後のOS全体に対する完全なkill-switch保証ではありません。実運用ではWireGuard設定と併せてOS firewallのegress kill switchを構成してください。

### Linuxプロセスメモリ保護 (実験的)

Cパネルの `[a]` はLinux上で `PR_SET_DUMPABLE=0`、`PR_SET_PTRACER=0`、soft `RLIMIT_CORE=0` を適用し、`/proc/self/status` の `TracerPid` を100ms間隔で監視します。保護中に作成するML-KEM共有秘密とAES鍵、および有効な送信セッション鍵には `mlock` と `MADV_DONTDUMP` を適用します。ページロックに失敗した暗号処理は継続せず、保護ONの設定を監視プロセスへ適用できない場合は起動を中止します。

この機能はASLRを超えるAMTD、メモリ配置の動的変換、デコイ検出を実装するものではありません。`mlock` はOS制限やメモリアロケータのページ共有に依存し、`MADV_DONTDUMP` は共有ページ全体に作用する可能性があります。暗号ライブラリ内部の複製、不変Pythonオブジェクト、スワップ、カーネル、root権限の攻撃者まで保護・消去できる保証はありません。TracerPid監視はポーリング方式であり、0.1ms応答を保証しません。Linux専用で、他OSでは有効化できません。ON/OFFはptrace許可状態を完全に復元する機能ではなく、軍事規格認証や完全な防御を意味しません。

このリポジトリのノートブックは空いているloopback portを選び、`cloudflared` で公開して `https://<random>.trycloudflare.com/rsi` を表示します。Colabの出力がLocalTunnel (`*.loca.lt`) やport `5000` を示す場合は、別のノートブックまたは古いランタイムが動いています。設定URLを取り違えないよう、Colab runtimeを再起動してこのリポジトリのnotebookを上から順に実行してください。トンネル確認では公開鍵pin、ML-KEM/AES-GCMの暗号要求・応答、認証拒否を検証します。

```bash
export COLAB_RSI_ENDPOINT="https://<your-authenticated-endpoint>/rsi"
export COLAB_RSI_TOKEN="<endpoint-token>"
export COLAB_RSI_PQ_PUBLIC_KEY_SHA256="<Colab-notebook-fingerprint>"
python airgap_ai_defender.py --rsi --ram-limit 1500
```

モデル同期では `--mode RSI` 起動時に `/model.sha256` と `/model` をHTTPSで定期取得します。URLはRSI endpointの `/rsi` をそれぞれ `/model.sha256` と `/model` に置き換えて自動構成します。別ホストやパスを使う場合は `ai_data/config.json` に `model_url` と `model_hash_url` を指定できます。`model_sync_interval` は秒単位（最小30秒）、`model_sync_token` は任意のBearer tokenです。SHA-256とモデル構造の検証に通らないファイルは配置せず、成功時のみ一時ファイルから原子的に置換します。上記の既知の旧形式はロード時に現行構造へ変換されますが、ハッシュ照合は引き続き必須です。実行中はメイン推論ループで新しい重みを適用します。

実装上、`/rsi`、`/model.sha256`、`/model` はすべて暗号化POSTです。直接のcurl/平文JSONやBearer headerによるAPI接続は使用しないでください。モデル同期も同じ鍵pinとML-KEM/AES-GCM処理を通します。

ローカルから送るのは `curated/curated_data.jsonl` の正常な数値特徴量（最大2048件）だけです。生パケットや通信内容は送信しません。APIはデータをキューへ入れてすぐに受理応答を返し、GPU学習はColab側で非同期に実行します。

RSI endpointへ送るのはタスク名、選別済み特徴量、学習設定、送信時刻だけです。モデルのstate_dictや生パケット、通信内容、学習データのファイル名・容量は送信しません。HTTPS以外の外部URLは拒否し、接続失敗時も通常の監視と既存の小バッチ学習を継続します。`--validation-only`ではエンドポイント未設定時に送信をシミュレートし、最大`--max-samples`件で終了します。

通常起動でも `COLAB_RSI_ENDPOINT` が未設定またはsudoへ引き継がれていない場合、RSI送信はシミュレーションになります。ログに `未設定のため送信をシミュレーション` と出る場合は、endpointを設定し、`sudo --preserve-env=COLAB_RSI_ENDPOINT,COLAB_RSI_TOKEN,COLAB_RSI_PQ_PUBLIC_KEY_SHA256` で起動してください。

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

成功時は終了コード `0` と `Head B のオンライン適合学習を 2 件で完了しました` のログを確認します。`--validation-only` はパケット監視を起動しません。検証はローカルデータを優先し、利用可能なデータがない場合にだけDriveから取得します。Drive上の教材を使う場合は、`--drive-id ""` を設定ファイルのDrive IDまたは実際のIDに置き換えてください。通常起動はデータ更新ワーカーがバックグラウンドで学習キューへデータを送ります。

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
sudo --preserve-env=COLAB_RSI_ENDPOINT,COLAB_RSI_TOKEN,COLAB_RSI_PQ_PUBLIC_KEY_SHA256 \
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

`airgap_ai_defender_6.py` は非推奨です（メンテナンス対象外、削除予定）。別実装です。既定では `./cloud_base_model.pth` を参照し、環境プロファイル、ハードニング、メモリ確認などを一度実行して終了します。通常版の継続的なパケット監視・データ更新処理と同じ機能を提供するものではありません。

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

## 開発ビルドと署名付きリリース

通常の開発では、`make check` と unittest は既存のPythonソースをそのまま使い、署名検証やCythonを要求しません。リリース生成だけで `make release` を使います。リリースビルドにはCython 3.0.12、C compiler、OpenSSL、ncurses開発ヘッダー、`strip` が必要です。ビルドは `airgap_ai_defender.py` と `mk1_usb_guard.py` をCython共有ライブラリにし、Cパネルをビルドしてstripした後、Ed25519署名とSHA-256サイドカーを作ります。モデルチェックポイントは自動で収集せず、署名対象に含めるファイルを `MK1AI_MODEL_FILES` にリポジトリ相対パスで改行区切り指定します。

秘密鍵はリポジトリへ保存せず、オフラインで生成して保管してください。CIを使う場合、GitHub Actionsの `release-signing` Environmentに `MK1AI_ED25519_PRIVATE_KEY` secretとしてPEMを登録し、Environmentのデプロイ保護ルールで署名可能なブランチ・タグを制限します。Workflowはmainへのpushと `v*` タグでビルド・署名・検証を行い、タグではGitHub Releaseも作成/更新します。秘密鍵を設定していない場合は署名工程を失敗させます。CI署名は設定済みの長期鍵によるため、Actionsと対象Environmentの保護が信頼境界です。

生成バンドルは `python3 scripts/verify_release.py --bundle dist/mk1ai-release --public-key /trusted/path/release-signing.pub` で検証できます。`scripts/run_release.sh BUNDLE_DIR TRUSTED_PUBLIC_KEY COMMAND [ARG ...]` は検証成功後に指定コマンドを実行します。公開鍵はバンドル同梱版をそのまま信頼せず、信頼済みの別経路で取得・固定してください。アプリを直接起動するとこのランチャー検証を迂回できます。これは共有ライブラリとパネルの署名済みパッケージングであり、全Pythonアプリをスタンドアロン化するものではありません。

## テスト

テストではPyTorch、NumPy、gdown、requests、psutil、cryptographyを使用します。実PyTorchがない場合はモデル・学習依存のテストをskipし、アプリ本体のstubを実PyTorchの代わりとしてテストしません。secure transportのテストはcryptographyとpqcryptoの両方がある場合だけ実行します。依存不足によるskipは成功を意味しないため、完全なテストには次のように依存を導入してください。

```bash
python3 -m venv .venv-mk1
.venv-mk1/bin/python -m pip install torch numpy psutil requests gdown
.venv-mk1/bin/python -m pip install -r requirements-secure-transport.txt
.venv-mk1/bin/python -m unittest discover -s tests -v
```

すでに仮想環境と依存を準備済みの場合は、最後のテストコマンドだけを実行します。テストの成功は、特定の補助関数の動作確認です。本番ネットワークでの検知精度、安全性、処理性能を保証するものではありません。
