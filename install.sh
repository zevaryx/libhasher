#!/bin/sh
set -e

echo "Installing into ~/.local/bin..."
mkdir -p ~/.local/bin

cd ~/.local/bin
wget "https://git.zevaryx.com/zevaryx/hasher-rs/releases/download/latest/hasher-gnu-linux-x86_64" -O ~/.local/bin/hasher-gnu-linux-x86_64
chmod +x ~/.local/bin/hasher-gnu-linux-x86_64
wget "https://git.zevaryx.com/zevaryx/hasher-rs/releases/download/latest/hasher-gnu-linux-x86_64.sha256" -O ~/.local/bin/hasher-gnu-linux-x86_64.sha256
sha256sum --status -c hasher-gnu-linux-x86_64.sha256 || exit 1
mv hasher-gnu-linux-x86_64 hasher
rm hasher-gnu-linux-x86_64.sha256

echo "Done! Add ~/.local/bin to your path to use!"