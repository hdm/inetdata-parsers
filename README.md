# Internet Data Processing Tools

Process internet data from various sources

## Dependencies

### Ubuntu
```
$ sudo apt-get install build-essential git make golang pigz p7zip-full libmtbl-dev mtbl-bin
```

### Build

Configure your GO environment if you haven't done so, by adding the following to ~/.bashrc

```
$ echo 'export GOPATH=$HOME' >> ~/.bashrc
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
```


