#!/bin/sh
set -e

ARCH=$(uname -m)
OS=$(uname -s)

if [ ! "$OS" = "Linux" ]; then
    echo "This script currently only works on Linux!"
    exit 1
fi

echo "Installing into ~/.local/bin..."
mkdir -p ~/.local/bin

cd ~/.local/bin
wget "https://git.zevaryx.com/zevaryx/hasher-rs/releases/download/latest/hasher-linux-$ARCH" -O ~/.local/bin/hasher-linux-$ARCH
wget "https://git.zevaryx.com/zevaryx/hasher-rs/releases/download/latest/hasher-linux-$ARCH.sha256" -O ~/.local/bin/hasher-linux-$ARCH.sha256
# Only make the download executable once it's verified, and don't leave a bad one behind
if ! sha256sum --status -c hasher-linux-$ARCH.sha256; then
    rm -f hasher-linux-$ARCH hasher-linux-$ARCH.sha256
    exit 1
fi
chmod +x ~/.local/bin/hasher-linux-$ARCH
mv hasher-linux-$ARCH hasher
rm hasher-linux-$ARCH.sha256

echo "Done! Add ~/.local/bin to your path to use!"