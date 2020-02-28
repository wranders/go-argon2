# go-argon2

- [Install](#install)
- [What is go-argon2 and how do I use it](#what-is-go-argon2-and-how-do-i-use-it)
- [Interface](#interface)
- [Configuration](#configuration)
- [License](#license)

---

## Install

```sh
go get github.com/wranders/go-argon2
```

---

## What is go-argon2 and how do I use it

This package is a interface for the `argon2` key derivation function using [`golang.org/x/crypto/argon2`](https://golang.org/x/crypto/argon2), aiming to provide the simplest interface.

The `Hasher` is what creates password hashes and is configured directly or generated from a comma-separated key-value string (perfect for storage in configuration files).

The `Matches` function generates parameters from the provided hash, so the `Hasher` is not needed.

```go
package main

import "github.com/wranders/go-argon2"

var hasher *argon2.Hasher

func main() {
    hasherSettings := "f=argon2id,s=16,k=32,m=65536,t=3,p=2"
    hasher, _ = argon2.NewHasherFromString(hasherSettings)
}

func HashPassword(password string) (string, error) {
    return hasher.Create(password)
}

func PaswordMatches(password, hash string) (bool, error) {
    return argon2.Matches(password, hash)
}
```

And that's it!

If you prefer to configure the `Hasher` directly:

```go
package main

import "github.com/wranders/go-argon2"

var hasher *argon2.Hasher

func main() {
    hasher = &argon2.Hasher{
        Form:        argon2.FormID,
        SaltLength:  16,
        KeyLength:   32,
        Memory:      65536,
        Iterations:  3,
        Parallelism: 2,
    }
}

func HashPassword(password string) (string, error) {
    return hasher.Create(password)
}

func PaswordMatches(password, hash string) (bool, error) {
    return argon2.Matches(password, hash)
}
```

---

## Interface

```go
const (
    FormI Form = iota + 1   //argon2i
    FormID                  //argon2id
)

type Form int

type Hasher struct {
    Form            Form
    Iterations      uint32
    KeyLength       uint32
    Memory          uint32
    Parallelism     uint8
    SaltLength      uint32
}

func Matches(string, string) (bool, error) {}
func NewHasherFromString(string) (*Hasher, error) {}
func (*Hasher) Create(string) (string, error) {}
```

```go
//Errors
type ErrIncompatibleVersion struct {}
type ErrInvalidForm struct{}
type ErrInvalidHash struct{}
type ErrInvalidHasherConfiguration struct{}
type ErrUnknownSetting struct {}
type ErrUnsupportedExpr struct {}
```

---

## Configuration

Creating a `Hasher` from a settings string is simple:

| Key | Value                  | Meaning                                                |
|:----|:-----------------------|:-------------------------------------------------------|
| `f` | `string`               | Form (`argon2i` or `argon2id`) (`argon2d` unsupported) |
| `s` | `uint32`               | Salt Length (`bytes`)                                  |
| `k` | `uint32`               | Key Length (`bytes`)                                   |
| `m` | `uint32` or Expression | Memory (`kibibytes`)                                   |
| `t` | `uint32`               | # Iterations over memory                               |
| `p` | `uint8`                | Parallelism (number of threads)                        |

```go
f=[string],s=[uint32],k=[uint32],m=[uint32|expr],t=[uint32],p=[uint8]
```

**Note:** Keys can be in any order, **as long as they're all there**

Memory can be any unsigned 32-bit number (`0` - `4294967295`), but expressions must evaluate between that range. The upper limit would use just under 550 GB of memory, to keep things in perspective.

`+`, `-`, `*`, `/`, `(`, `)`, and `space` are the only valid non-numeric characters in memory expressions.

```go
f=argon2i,s=16,k=32,m=64*1024,t=3,p=2

f=argon2i,s=16,k=32,m=((64*1024) + (20-10))/2,t=3,p=2
```

Both are valid for use with `NewHasherFromString`. Expressions remove the need to pre-calculate kibibyte values.

---

## License

Copyright &copy; 2020 [W Anders](https://github.com/wranders)

Licensed under [MIT License](https://github.com/wranders/go-argon2/blob/master/LICENSE
)
