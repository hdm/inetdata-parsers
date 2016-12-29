domains=$( curl -s https://publicsuffix.org/list/public_suffix_list.dat | \
grep -v '^//' | \
grep "\\." | \
rev | sort | rev | \
awk '{print "\""$1"\","}' )

echo -ne "package main\n" > public_suffixes.go
echo -ne "var Public_Suffixes = []string{" >> public_suffixes.go
echo -ne $domains >> public_suffixes.go
echo -ne "}" >> public_suffixes.go
go fmt public_suffixes.go
