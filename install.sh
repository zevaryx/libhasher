#!/bin/sh
set -e

ARCH=$(uname -m)
OS=$(uname -s)
unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    MSYS_NT*)   machine=MSys;;
    *)          machine="UNKNOWN:${unameOut}"
esac

if [ ! "$OS" -eq "Linux" ]; then
    echo "This script currently only works on Linux!"
    exit 1
fi

echo "Installing into ~/.local/bin..."
mkdir -p ~/.local/bin

cd ~/.local/bin
wget "https://git.zevaryx.com/zevaryx/hasher-rs/releases/download/latest/hasher-linux-$ARCH" -O ~/.local/bin/hasher-linux-$ARCH
chmod +x ~/.local/bin/hasher-linux-$ARCH
wget "https://git.zevaryx.com/zevaryx/hasher-rs/releases/download/latest/hasher-linux-$ARCH.sha256" -O ~/.local/bin/hasher-linux-$ARCH.sha256
sha256sum --status -c hasher-linux-$ARCH.sha256 || exit 1
mv hasher-linux-$ARCH hasher
rm hasher-linux-$ARCH.sha256

echo "Done! Add ~/.local/bin to your path to use!"