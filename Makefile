ALL:
	@go get -u ./... && \
	go fmt ./... && \
	go build ./... && \
	go install ./... && \
	echo "[*] Installed binaries in ${GOPATH}/bin"

.PHONY: ALL
