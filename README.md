# fips-golang

![](https://github.com/PreVeil/fips-golang/workflows/CI/badge.svg)

Go bindings for [fips-crypto](https://github.com/PreVeil/fips-crypto).

For dev, should have

`/usr/local/lib/libfips-crypto.dylib`

and

`/usr/local/include/fips-crypto/fips-crypto.h`

For prod, just have to set `FIPSPATH=<X>`,
where X must contain `fips-crypto/fips-crypto.h` and `libfips-crypto.dylib`
