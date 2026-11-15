#!/usr/bin/env bash
# Standalone SOCKS5 installer for jieshu production repo; no portbw or VLESS changes.
set -Eeuo pipefail
umask 077
[[ ${EUID:-999} -eq 0 ]] || { echo '请使用 root' >&2; exit 1; }
DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION="${1:-install}"
S5_3PROXY_CHANNEL="${S5_3PROXY_CHANNEL:-lts}"
case "$S5_3PROXY_CHANNEL" in
  lts) S5_3PROXY_SUITE=lts ;;
  stable) S5_3PROXY_SUITE=current ;;
  *) echo 'S5_3PROXY_CHANNEL 只能为 lts 或 stable' >&2;exit 2;;
esac
case "$ACTION" in
  install|update) shift || true ;;
  deps) ;;
  *) echo '用法：bash socks5-install.sh install --wan-if eth0 --host 1.2.3.4 | update | deps' >&2;exit 2;;
esac

# Sources may be local or fetched from a selected jieshu release branch.
# SHA256 pinning prevents mixing a new installer with an old manager.
FETCH_DIR=''
fetch_cleanup(){
  if [[ -n "${FETCH_DIR:-}" && -d "$FETCH_DIR" ]];then rm -rf -- "$FETCH_DIR";fi
}
trap fetch_cleanup EXIT
if [[ "$ACTION" != deps ]];then
  if [[ -f "$DIR/socks5.py" && -f "$DIR/socks5-traffic.py" && -f "$DIR/socks5-audit.py" ]];then
    SRC_DIR="$DIR"
  else
    command -v curl >/dev/null || { echo '缺少 curl；请先安装 curl ca-certificates' >&2;exit 1; }
    FETCH_DIR="$(mktemp -d /tmp/socks5-source.XXXXXXXX)"
    chmod 0700 "$FETCH_DIR"
    S5_SOURCE_REF="${S5_SOURCE_REF:-main}"
    case "$S5_SOURCE_REF" in
      main|feature/socks5-access-audit) ;;
      *) echo '拒绝未知源码分支，请使用 main 或 feature/socks5-access-audit' >&2; exit 1 ;;
    esac
    RAW="https://raw.githubusercontent.com/liucong552-art/jieshu/$S5_SOURCE_REF"
    curl -fsSL --retry 3 --connect-timeout 10 --max-time 90 "$RAW/socks5.py" -o "$FETCH_DIR/socks5.py"
    curl -fsSL --retry 3 --connect-timeout 10 --max-time 90 "$RAW/socks5-traffic.py" -o "$FETCH_DIR/socks5-traffic.py"
    curl -fsSL --retry 3 --connect-timeout 10 --max-time 90 "$RAW/socks5-audit.py" -o "$FETCH_DIR/socks5-audit.py"
    SRC_DIR="$FETCH_DIR"
    echo "[socks5] 从 jieshu/$S5_SOURCE_REF 下载三个 SOCKS5 模块..."
  fi
  expected_core="712bb120e4d8fbc61d163c4655172698b45a028b20b01062eb3cc02a2f93aecd"
  expected_traffic="1361a91419dbe9236960f7f5cfa6f75a439c45d3af2ae1de2192192c81fcde7e"
  expected_audit="3c6e1bb357959e12d04c9adf2ba0a99f51ca349c4b812f8b6981259843acf7c8"
  actual_audit="$(sha256sum "$SRC_DIR/socks5-audit.py" | awk '{print $1}')"
  actual_core="$(sha256sum "$SRC_DIR/socks5.py" | awk '{print $1}')"
  actual_traffic="$(sha256sum "$SRC_DIR/socks5-traffic.py" | awk '{print $1}')"
  [[ "$actual_audit" == "$expected_audit" ]] || { echo 'socks5-audit.py SHA256 不匹配；停止安装' >&2;exit 1; }
  [[ "$actual_core" == "$expected_core" ]] || { echo 'socks5.py SHA256 不匹配；停止安装' >&2;exit 1; }
  [[ "$actual_traffic" == "$expected_traffic" ]] || { echo 'socks5-traffic.py SHA256 不匹配；停止安装' >&2;exit 1; }
  echo '[socks5] SHA256 校验通过'
fi
install_dependencies(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -o Acquire::Retries=3
  apt-get install -y ca-certificates curl gnupg python3 nftables iproute2 util-linux coreutils procps
  if [[ "$S5_3PROXY_CHANNEL" == lts ]];then
    if command -v 3proxy >/dev/null 2>&1;then return;fi
    if apt-cache show 3proxy >/dev/null 2>&1;then apt-get install -y 3proxy;fi
    if command -v 3proxy >/dev/null 2>&1;then return;fi
  fi
  keytmp="$(mktemp)"
  trap 'rm -f -- "$keytmp"' RETURN
  curl -fLsS --connect-timeout 10 --max-time 60 'https://3proxy.org/repo/3proxy-release-key.asc' -o "$keytmp"
  fingerprint="$(gpg --batch --quiet --show-keys --with-colons "$keytmp" | awk -F: '$1=="fpr" {print toupper($10);exit}')"
  [[ "$fingerprint" == 'FC12214499FCC7BA1CFF6CDC0312384E3A73940B' ]] || { echo "不可信的 3proxy signing key: $fingerprint" >&2;exit 1; }
  install -m 0644 "$keytmp" /usr/share/keyrings/socks5-3proxy.asc
  cat >/etc/apt/sources.list.d/socks5-3proxy.sources <<EOF
Types: deb
URIs: https://3proxy.org/repo/deb
Suites: $S5_3PROXY_SUITE
Components: main
Signed-By: /usr/share/keyrings/socks5-3proxy.asc
EOF
  apt-get update -o Acquire::Retries=3
  apt-get install -y 3proxy
  command -v 3proxy >/dev/null || { echo '3proxy 安装失败' >&2;exit 1; }
}
if [[ "$ACTION" == deps ]];then install_dependencies;exit 0;fi
if [[ "${AUTO_DEPS:-0}" == 1 ]];then
  if [[ "$S5_3PROXY_CHANNEL" == stable ]];then
    install_dependencies
  else
    for name in 3proxy python3 nft ip ss timeout flock;do
      if ! command -v "$name" >/dev/null 2>&1;then install_dependencies;break;fi
    done
  fi
fi
for name in 3proxy python3 nft ip ss timeout systemctl flock;do
  command -v "$name" >/dev/null || { echo "缺少 $name；运行 AUTO_DEPS=1 bash socks5-install.sh install ..." >&2;exit 1; }
done
python3 -B - "$SRC_DIR/socks5.py" "$SRC_DIR/socks5-traffic.py" "$SRC_DIR/socks5-audit.py" <<'PY'
import sys
for name in sys.argv[1:]:
    with open(name,'rb') as f:compile(f.read(),name,'exec')
PY
install -d -m 0755 /usr/local/lib/socks5-manager /usr/local/sbin
install -d -m 0700 /run/socks5-manager
exec 9>/run/socks5-manager/install.lock
flock -w 120 9 || { echo 'SOCKS5 安装锁繁忙' >&2;exit 1; }
TARGETS=(/usr/local/lib/socks5-manager/socks5.py /usr/local/lib/socks5-manager/traffic.py /usr/local/lib/socks5-manager/audit.py /usr/local/sbin/socks5 /usr/local/sbin/socks5-traffic)
SUCCESS=0
TX="$(mktemp -d /var/tmp/socks5-install.XXXXXX)"
cleanup(){
  rc=$?;trap - EXIT ERR INT TERM HUP
  if [[ "$SUCCESS" != 1 ]];then
    for idx in "${!TARGETS[@]}";do
      path="${TARGETS[$idx]}"
      if [[ -f "$TX/$idx.present" ]];then
        tmp="$(mktemp "${path}.rollback.XXXXXX")"
        cp -a -- "$TX/$idx.old" "$tmp" && mv -f -- "$tmp" "$path"
      elif [[ -f "$TX/$idx.absent" ]];then
        rm -f -- "$path"
      fi
    done
    echo '已尝试回滚 SOCKS5 程序文件。' >&2
  fi
  for path in "${TARGETS[@]}";do
    for temp in "${path}.stage."* "${path}.rollback."*;do
      [[ -e "$temp" ]] && rm -f -- "$temp"
    done
  done
  rm -rf -- "$TX"
  fetch_cleanup
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
for idx in "${!TARGETS[@]}";do
  path="${TARGETS[$idx]}"
  [[ ! -L "$path" ]] || { echo "拒绝覆盖符号链接：$path" >&2;exit 1; }
  if [[ -e "$path" || -L "$path" ]];then
    cp -a -- "$path" "$TX/$idx.old";: >"$TX/$idx.present"
  else
    : >"$TX/$idx.absent"
  fi
done
atomic_install(){
  src="$1"; target="$2"; mode="$3"
  tmp="$(mktemp "${target}.stage.XXXXXX")"
  install -m "$mode" "$src" "$tmp"
  mv -f -- "$tmp" "$target"
}
atomic_install "$SRC_DIR/socks5.py" /usr/local/lib/socks5-manager/socks5.py 0700
atomic_install "$SRC_DIR/socks5-traffic.py" /usr/local/lib/socks5-manager/traffic.py 0700
atomic_install "$SRC_DIR/socks5-audit.py" /usr/local/lib/socks5-manager/audit.py 0700
cat >"$TX/socks5.wrapper" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exec /usr/bin/python3 /usr/local/lib/socks5-manager/socks5.py "$@"
EOF
cat >"$TX/socks5-traffic.wrapper" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
export PYTHONPATH=/usr/local/lib/socks5-manager
exec /usr/bin/python3 /usr/local/lib/socks5-manager/traffic.py "$@"
EOF
chmod 0755 "$TX/socks5.wrapper" "$TX/socks5-traffic.wrapper"
atomic_install "$TX/socks5.wrapper" /usr/local/sbin/socks5 0755
atomic_install "$TX/socks5-traffic.wrapper" /usr/local/sbin/socks5-traffic 0755
/usr/local/sbin/socks5 install "$@"
SUCCESS=1
