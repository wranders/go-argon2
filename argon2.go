// Package argon2 provides a simplified interface for the argon2
// key derivation function using https://golang.org/x/crypto/argon2.
//
// Configuration is handled by creating a Hasher structure with all
// attributes populated, or by passing a comma-delimited key-value
// string to the NewHasherFromString function. The Hasher structure
// possesses the functions to create and verify password hashes.
//
// argon2i and argon2id are the only supported variants.
//
//	func WithString() {
//	    settings := "f=argon2id,s=16,k=32,m=65536,t=3,p=2"
//	    hasher, _ := argon2.NewHasherFromString(settings)
//
//	    hashPass, _ := hasher.Create("mySecretPassword")
//
//	    if ok, _ := hasher.Matches("mySecretPassword", hashPass); ok {
//	        fmt.Println("Pasword matches!")
//	    } else {
//	        fmt.Println("Password does not match!")
//	    }
//	}
//
//	func WithStruct() {
//	    hasher := &argon2.Hasher{
//	        Form:        argon2.FormI,
//	        SaltLength:  16,
//	        KeyLength:   32
//	        Memory:      65536,
//	        Iterations:  3,
//	        Parallelism: 2,
//	    }
//
//	    hashPass, _ := hasher.Create("mySecretPassword")
//
//	    if ok, _ := hasher.Matches("mySecretPassword", hashPass); ok {
//	        fmt.Println("Pasword matches!")
//	    } else {
//	        fmt.Println("Password does not match!")
//	    }
//	}
//
// When using a string to initialize the Hasher, a mathematical
// expression can be used to configure memory settings (ie `64*1024`)
// so kibibyte values do not need to be calculated beforehand.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Form is the type of argon2 to use
type Form int

const (
	// FormI represents the `argon2i` variant
	FormI Form = iota + 1

	// FormID represents the `argon2id` variant
	FormID
)

// Hasher contains the parameters used by the argon2
type Hasher struct {
	// `argon2.FormI` or `argon2.FormID`
	Form Form

	// (s) Byte length of hash salt
	SaltLength uint32

	// (k) Byte length of hash key
	KeyLength uint32

	// (m) Amount of memory (in kibibytes) to use
	Memory uint32

	// (t) Number of iterations to perform
	Iterations uint32

	// (p) Degree of parallelism; number of threads
	Parallelism uint8
}

// Create an argon2 hash of a plain-text password
//
// Errors:
//  *ErrInvalidForm
//  *ErrInvalidHasherConfiguration
//  io.ErrShortBuffer       (only if problem with system RNG)
//  io.ErrUnexpectedEOF     (only if problem with system RNG)
func (h *Hasher) Create(password string) (string, error) {
	return h.hashCreate(password)
}

// Matches compares a plain-text password with a provided argon2
// hash, returning true or false if they match
//
// Errors:
//  *ErrInvalidHash
//  *ErrInvalidForm
//  *ErrIncompatibleVersion
//  base64.CorruptInputError
func Matches(password, hash string) (bool, error) {
	return hashCompare(password, hash)
}

// NewHasherFromString parses a comma-delimited key-value string into
// a Hasher structure used to configure argon2. All fields must be
// present to configure argon2 as there are no default values.
//
// Configuration string format:
//
// "f": Form (string) : "argon2i" or "argon2id"
//
// "s": Salt Length (int) : Byte length of hash salt
//
// "k": Key Length (int) : Byte length of hash key
//
// "m": Memory (int OR expression) :
// Memory is evaluated, so mathematical expressions can be used.
//
// "t": Time/Iterations (int) : Number of passes over memory
//
// "p": Parallelism (int) : Number of threads
//
// Errors:
//  *ErrInvalidForm
//  *ErrUnknownSetting
//  scanner.ErrorList
//  *strconv.NumError (int in expression larger than 32-bit)
func NewHasherFromString(settings string) (*Hasher, error) {
	hasher := &Hasher{}
	valueSlice := strings.Split(settings, ",")
	for _, v := range valueSlice {
		switch v[0:2] {
		case "f=":
			var form string
			_, err := fmt.Sscanf(v, "f=%s", &form)
			if err != nil {
				return nil, err
			}
			switch form {
			case "argon2i":
				hasher.Form = FormI
			case "argon2id":
				hasher.Form = FormID
			default:
				return nil, &ErrInvalidForm{}
			}
		case "s=":
			var saltLength uint32
			_, err := fmt.Sscanf(v, "s=%d", &saltLength)
			if err != nil {
				return nil, err
			}
			hasher.SaltLength = saltLength
		case "k=":
			var keylength uint32
			_, err := fmt.Sscanf(v, "k=%d", &keylength)
			if err != nil {
				return nil, err
			}
			hasher.KeyLength = keylength
		case "m=":
			memory, err := parseMemory(v[2:])
			if err != nil {
				return nil, err
			}
			hasher.Memory = memory
		case "t=":
			var iterations uint32
			_, err := fmt.Sscanf(v, "t=%d", &iterations)
			if err != nil {
				return nil, err
			}
			hasher.Iterations = iterations
		case "p=":
			var parallelism uint8
			_, err := fmt.Sscanf(v, "p=%d", &parallelism)
			if err != nil {
				return nil, err
			}
			hasher.Parallelism = parallelism
		default:
			return nil, &ErrUnknownSetting{v[0:1]}
		}
	}
	return hasher, nil
}

func (h *Hasher) isValid() bool {
	if int(h.Form) > 0 && h.SaltLength > 0 &&
		h.KeyLength > 0 && h.Memory > 0 &&
		h.Iterations > 0 && h.Parallelism > 0 {
		return true
	}
	return false
}

func (h *Hasher) hashCreate(password string) (string, error) {
	if !h.isValid() {
		return "", &ErrInvalidHasherConfiguration{}
	}
	salt := make([]byte, h.SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	passwordBytes := []byte(password)
	var form string
	var key []byte
	switch h.Form {
	case FormI:
		form = "argon2i"
		key = argon2.Key(
			passwordBytes,
			salt,
			h.Iterations,
			h.Memory,
			h.Parallelism,
			h.KeyLength,
		)
	case FormID:
		form = "argon2id"
		key = argon2.IDKey(
			passwordBytes,
			salt,
			h.Iterations,
			h.Memory,
			h.Parallelism,
			h.KeyLength,
		)
	default:
		return "", &ErrInvalidForm{}
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)
	hash := fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		form,
		argon2.Version,
		h.Memory,
		h.Iterations,
		h.Parallelism,
		b64Salt,
		b64Key,
	)
	return hash, nil
}

func hashCompare(password, hash string) (bool, error) {
	hashValues := strings.Split(hash, "$")
	if len(hashValues) != 6 {
		return false, &ErrInvalidHash{}
	}
	var hashForm Form
	switch hashValues[1] {
	case "argon2i":
		hashForm = FormI
	case "argon2id":
		hashForm = FormID
	default:
		return false, &ErrInvalidForm{}
	}

	var hashVersion int
	_, err := fmt.Sscanf(hashValues[2], "v=%d", &hashVersion)
	if err != nil {
		return false, err
	}
	if hashVersion != argon2.Version {
		return false, &ErrIncompatibleVersion{hashVersion}
	}

	var hashMemory uint32
	var hashIterations uint32
	var hashParallelism uint8
	_, err = fmt.Sscanf(
		hashValues[3],
		"m=%d,t=%d,p=%d",
		&hashMemory,
		&hashIterations,
		&hashParallelism,
	)
	if err != nil {
		return false, err
	}

	hashSalt, err := base64.RawStdEncoding.DecodeString(hashValues[4])
	if err != nil {
		return false, err
	}

	hashKey, err := base64.RawStdEncoding.DecodeString(hashValues[5])
	if err != nil {
		return false, err
	}
	hashKeyLength := uint32(len(hashKey))

	pwbytes := []byte(password)
	var passwordKey []byte
	switch hashForm {
	case FormI:
		passwordKey = argon2.Key(
			pwbytes,
			hashSalt,
			hashIterations,
			hashMemory,
			hashParallelism,
			hashKeyLength,
		)
	case FormID:
		passwordKey = argon2.IDKey(
			pwbytes,
			hashSalt,
			hashIterations,
			hashMemory,
			hashParallelism,
			hashKeyLength,
		)
	default:
		return false, &ErrInvalidForm{}
	}

	hashKeyLen := int32(len(hashKey))
	passwordKeyLen := int32(len(passwordKey))

	if subtle.ConstantTimeEq(hashKeyLen, passwordKeyLen) == 0 {
		return false, nil
	}
	if subtle.ConstantTimeCompare(hashKey, passwordKey) == 1 {
		return true, nil
	}

	return false, nil
}

func parseMemory(exp string) (uint32, error) {
	tree, err := parser.ParseExpr(exp)
	if err != nil {
		return 0, err
	}
	return evalMemory(tree)
}

func evalMemory(tree ast.Expr) (uint32, error) {
	switch n := tree.(type) {
	case *ast.BasicLit:
		if n.Kind != token.INT {
			return 0, &ErrUnsupportedExpr{n.Kind}
		}
		u, err := strconv.ParseUint(n.Value, 10, 32)
		if err != nil {
			return 0, err
		}
		return uint32(u), nil
	case *ast.BinaryExpr:
		switch n.Op {
		case token.ADD, token.SUB, token.MUL, token.QUO:
		default:
			return 0, &ErrUnsupportedExpr{n.Op}
		}
		x, err := evalMemory(n.X)
		if err != nil {
			return 0, err
		}
		y, err := evalMemory(n.Y)
		if err != nil {
			return 0, err
		}
		switch n.Op {
		case token.ADD:
			return x + y, nil
		case token.SUB:
			return x - y, nil
		case token.MUL:
			return x * y, nil
		case token.QUO:
			return x / y, nil
		}
	case *ast.ParenExpr:
		return evalMemory(n.X)
	}
	return 0, &ErrUnsupportedExpr{reflect.TypeOf(tree)}
}
