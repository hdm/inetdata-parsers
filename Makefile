VERSION=`cat VERSION`

LDFLAGS="-X github.com/hdm/inetdata-parsers/utils.Version=${VERSION}"
ALL:
	@pkg-config --exists libmtbl || (echo "Missing libmtbl: sudo apt install libmtbl-dev" && exit 1)
	@go get github.com/mitchellh/gox && \
	go get -u ./... && \
	go fmt ./... && \
	go build -ldflags=${LDFLAGS} ./... && \
	go install ./... && \
	gox -ldflags=${LDFLAGS} -output="release/${VERSION}/{{.OS}}-{{.Arch}}/{{.Dir}}" -osarch="linux/amd64" ./... && \
	sudo cp release/${VERSION}/*/* /usr/local/bin

.PHONY: ALL
