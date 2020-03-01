package argon2

import "fmt"

// ErrIncompatibleVersion is returned if a different version of
// argon2 is used in the hash
type ErrIncompatibleVersion struct {
	version int
}

func (e ErrIncompatibleVersion) Error() string {
	return fmt.Sprintf("Incompatible version of argon2: %d", e.version)
}

// ErrInvalidForm is returned if the argon2 variant is unrecognized
type ErrInvalidForm struct{}

func (e ErrInvalidForm) Error() string {
	return fmt.Sprint("Unknown or unsupported argon2 form")
}

// ErrInvalidHash is returned if the provided hash is incorrectly
// formatted or missing crucial information.
type ErrInvalidHash struct{}

func (e ErrInvalidHash) Error() string {
	return fmt.Sprint("Hash is not in the correct format")
}

// ErrInvalidHasherConfiguration returns if the hasher configuration
// contains invalid parameters or if not all parameters are set.
type ErrInvalidHasherConfiguration struct{}

func (e ErrInvalidHasherConfiguration) Error() string {
	return fmt.Sprint("Argon2 configuration contains invalid values")
}

// ErrUnknownSetting returns if a setting string contains an
// unknown key
type ErrUnknownSetting struct {
	setting string
}

func (e ErrUnknownSetting) Error() string {
	return fmt.Sprintf("Unknown argon2 setting: %s", e.setting)
}

// ErrUnsupportedExpr returns if part of an evaluated string
// expression contains non-integers or unsupported modifiers.
type ErrUnsupportedExpr struct {
	kind interface{}
}

func (e ErrUnsupportedExpr) Error() string {
	return fmt.Sprintf("`%v` unsupported in argon2 memory expression", e.kind)
}
