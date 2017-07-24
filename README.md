# Internet Data Processing Tools

Process internet data from various sources

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
$ echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
$ echo 'export GOPATH=$HOME' >> ~/.bashrc
$ source ~/.bashrc
```

Clone this repository into the correct path:
```
$ mkdir -p $GOPATH/src/github.com/fathom6/
$ cd $GOPATH/src/github.com/fathom6/
$ git clone https://github.com/fathom6/inetdata-parsers.git
```

### Install
```
$ cd $GOPATH/src/github.com/fathom6/inetdata-parsers/
$ make
```


