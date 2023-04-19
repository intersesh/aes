# AES

[![Go Reference](https://pkg.go.dev/badge/github.com/ny0m/aes.svg)](https://pkg.go.dev/github.com/ny0m/aes)

This repo contains an implementation of the Rijndael encryption algorithm
as described in the [NIST FIPS 197 AES paper](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf).

Although the public API of this package adheres to common Go patterns,
the internals strive to closely implement the details of the FIPS paper,
so you should be able to easily use this package and the paper alongside one another.

This package aims to be clear and easy to read, rather than efficient,
and may contain bugs. Do not use this package for real cryptography.