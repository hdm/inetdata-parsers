ALL:
	@pkg-config --exists libmtbl || (echo "Missing libmtbl: sudo apt install libmtbl-dev" && exit 1)
	@go get github.com/mitchellh/gox && \
	go get -u ./... && \
	go fmt ./... && \
	go vet ./... && \
	go build ./... && \
	go install ./... && \
	gox -output="release/{{.OS}}-{{.Arch}}/{{.Dir}}" -osarch="linux/amd64" ./... && \
	sudo cp release/*/* /usr/local/bin

.PHONY: ALL
