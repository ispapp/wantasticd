#!/bin/sh

# This script installs the wantasticd agent.

# Exit on error
set -e

#
# detect_os_arch detects the operating system and architecture.
#
detect_os_arch() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"

  case "$OS" in
    linux)
      OS="linux"
      ;;
    darwin)
      OS="darwin"
      ;;
    *)
      echo "Unsupported OS: $OS"
      exit 1
      ;;
  esac

  case "$ARCH" in
    x86_64)
      ARCH="amd64"
      ;;
    arm64)
      ARCH="arm64"
      ;;
    aarch64)
      ARCH="arm64"
      ;;
    *)
      echo "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac

  echo "Detected OS: $OS"
  echo "Detected architecture: $ARCH"
}

#
# download_latest_release downloads the latest release from GitHub.
#
download_latest_release() {
  LATEST_RELEASE=$(curl -s "https://api.github.com/repos/wantastic/wantasticd/releases/latest" | grep -o '"tag_name": ".*"' | sed 's/"tag_name": "//' | sed 's/"//')
  DOWNLOAD_URL="https://github.com/wantastic/wantasticd/releases/download/$LATEST_RELEASE/wantasticd-$OS-$ARCH"

  echo "Downloading from: $DOWNLOAD_URL"
  curl -L -o wantasticd "$DOWNLOAD_URL"
}

#
# install_binary installs the wantasticd binary.
#
install_binary() {
  chmod +x wantasticd

  if [ -w "/usr/local/bin" ]; then
    mv wantasticd /usr/local/bin/
  else
    echo "You do not have write access to /usr/local/bin. Trying with sudo."
    sudo mv wantasticd /usr/local/bin/
  fi

  echo "wantasticd installed successfully!"
}

#
# handle_login handles the login process.
#
handle_login() {
  if [ -n "$1" ]; then
    wantasticd login --token "$1"
  else
    wantasticd login
  fi
}

main() {
  detect_os_arch
  download_latest_release
  install_binary
  handle_login "$@"
}

main "$@"
