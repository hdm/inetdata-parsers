
#!/bin/bash
bins=$(find cmd -maxdepth 1 -type d | grep / | cut -f 2 -d / | sort)
for bin in ${bins}; do
  echo "[*] Building ${bin}..."
  go build -o bin/${bin} cmd/${bin}/main.go || exit
done
