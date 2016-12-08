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
export GOPATH=$HOME
```

Load the profile settings:
```
$ source ~/.bashrc
```

Run the build script:
```
$ ./build.sh
```

### Install
```
$ sudo cp bin/* /usr/local/bin/
```


