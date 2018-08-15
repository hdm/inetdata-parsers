# Internet Data Processing Tools

Process internet data from various sources. Works with [inetdata](https://github.com/hdm/inetdata)

## Dependencies

### Ubuntu 16.04
```
$ sudo apt-get install build-essential git make pigz p7zip-full libmtbl-dev mtbl-bin pkg-config
```

### Golang
* Download the latest golang binary (1.8+) from https://golang.org/dl/
* Extract to the filesystem with:
``` # tar -C /usr/local -xzf go$VERSION.$OS-$ARCH.tar.gz```

### Build

Configure your GO environment if you haven't done so, by adding the following to ~/.bashrc

```
$ echo 'export GOPATH=$HOME' >> ~/.bashrc
$ echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> ~/.bashrc

$ source ~/.bashrc
```

Clone this repository into the correct path:
```
$ mkdir -p $GOPATH/src/github.com/hdm/
$ cd $GOPATH/src/github.com/hdm/
$ git clone https://github.com/hdm/inetdata-parsers.git
```

### Install
```
$ cd $GOPATH/src/github.com/hdm/inetdata-parsers/
$ make

Number of parallel builds: 3
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/mapi
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/mq
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-arin-xml2json
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-csvsplit
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-arin-org2cidrs
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-csv2mtbl
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-dns2mtbl
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-ct2csv
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-ct2hostnames
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-ct2hostnames-sync
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-ct2mtbl
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-csvrollup
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-lines2mtbl
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-hostnames2domains
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-json2mtbl
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-sonardnsv2-split
-->     linux/amd64: github.com/fathom6/inetdata-parsers/cmd/inetdata-zone2csv

```


