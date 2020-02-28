package argon2

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"testing"
)

const (
	password                         string = "mySecretPassword"
	wrongPassword                    string = "MySecretPassword"
	settingArgon2I                   string = "f=argon2i,s=16,k=32,m=65536,t=3,p=2"
	settingArgon2D                   string = "f=argon2d,s=16,k=32,m=65536,t=3,p=2"
	settingArgon2ID                  string = "f=argon2id,s=16,k=32,m=65536,t=3,p=2"
	settingArgon2IDExpr              string = "f=argon2id,s=16,k=32,m=( ( 64 * 1024 ) + ( 20 - 10 ) ) / 2,t=3,p=2"
	settingArgon2IDExprInvalidBin    string = "f=argon2id,s=16,k=32,m=((64%1024)+(20-10))/2,t=3,p=2"
	settingArgon2IDExprInvalidSigned string = "f=argon2id,s=16,k=32,m=((64*-1024)+(20-10))/2,t=3,p=2"
	settingArgon2IDExprInvalidMax    string = "f=argon2id,s=16,k=32,m=((64*4294967300)+(20-10))/2,t=3,p=2"
	settingArgon2IDExprInvalidType   string = "f=argon2id,s=16,k=32,m=((64*(3.14159))+(20-10))/2,t=3,p=2"
	settingArgon2IDExtra             string = "f=argon2id,s=16,k=32,m=65536,t=3,p=2,j=9"
	settingArgon2IDMissing           string = "f=argon2id,s=16,k=32,m=65536,p=2"
	hashCorruptSalt                  string = "$argon2i$v=19$m=65536,t=3,p=2$oOT8PmX+YLmj8wReAP0Cg$uIP1h5Z1DOSx9YBBSWOHE84AYGxC9/GwnB3ZFGZFh8E"
	hashCorruptKey                   string = "$argon2i$v=19$m=65536,t=3,p=2$oOT8PmX+YLmj8wRveAP0Cg$uIP1h5Z1DOSx9YBBSWOHE84AYGxC9GwnB3ZFGZFh8E"
	hashInvalidForm                  string = "$argon2d$v=19$m=65536,t=3,p=2$oOT8PmX+YLmj8wRveAP0Cg$uIP1h5Z1DOSx9YBBSWOHE84AYGxC9/GwnB3ZFGZFh8E"
	hashIncompatVersion              string = "$argon2i$v=13$m=65536,t=3,p=2$oOT8PmX+YLmj8wRveAP0Cg$uIP1h5Z1DOSx9YBBSWOHE84AYGxC9/GwnB3ZFGZFh8E"
)

func TestMatchHashIncompatVersion(t *testing.T) {
	_, err := Matches(password, hashIncompatVersion)
	if err == nil {
		t.Errorf("MatchHashIncompatVersion_NoErr: %w", err)
	}
	if _, ok := err.(*ErrIncompatibleVersion); !ok {
		t.Errorf("MatchHashIncompatVersion_WrongErr: %T", err)
	}
}

func TestMatchHashInvalidForm(t *testing.T) {
	_, err := Matches(password, hashInvalidForm)
	if err == nil {
		t.Errorf("MatchHashInvalidForm_NoErr: %w", err)
	}
	if _, ok := err.(*ErrInvalidForm); !ok {
		t.Errorf("MatchHashInvalidForm_WrongErr: %T", err)
	}
}

func TestMatchHashInvalid(t *testing.T) {
	_, err := Matches(password, settingArgon2IDMissing)
	if err == nil {
		t.Errorf("MatchHashInvalid_NoErr: %w", err)
	}
	if _, ok := err.(*ErrInvalidHash); !ok {
		t.Errorf("MatchHashInvalid_WrongErr: %T", err)
	}
}

func TestHasherInvalidForm(t *testing.T) {
	hasher := &Hasher{
		Form:        Form(7),
		SaltLength:  16,
		KeyLength:   32,
		Memory:      65536,
		Iterations:  3,
		Parallelism: 2,
	}
	_, err := hasher.Create(password)
	if err == nil {
		t.Errorf("InvalidForm_NoErr: %w", err)
	}
	if _, ok := err.(*ErrInvalidForm); !ok {
		t.Errorf("InvalidForm_WrongErr: %T", err)
	}
}

func TestHasherIncompleteStruct(t *testing.T) {
	hasher := &Hasher{
		Form:        FormI,
		SaltLength:  16,
		KeyLength:   32,
		Memory:      65536,
		Parallelism: 2,
	}
	_, err := hasher.Create(password)
	if err == nil {
		t.Errorf("IncompleteStruct_NoErr: %w", err)
	}
	if _, ok := err.(*ErrInvalidHasherConfiguration); !ok {
		t.Errorf("IncompleteStruct_WrongErr: %T", err)
	}
}

func TestHasherExtraSetting(t *testing.T) {
	_, err := NewHasherFromString(settingArgon2IDExtra)
	if err == nil {
		t.Errorf("ExtraSetting_NoErr: %w", err)
	}
	if _, ok := err.(*ErrUnknownSetting); !ok {
		t.Errorf("ExtraSetting_WrongErr: %T", err)
	}
}

func TestMatchCorruptKey(t *testing.T) {
	_, err := Matches(password, hashCorruptSalt)
	if err == nil {
		t.Errorf("MatchCorruptKey_NoErr: %w", err)
	}
	if _, ok := err.(base64.CorruptInputError); !ok {
		t.Errorf("MatchCorruptKey_WrongErr: %T", err)
	}
}

func TestMatchCorruptSalt(t *testing.T) {
	_, err := Matches(password, hashCorruptSalt)
	if err == nil {
		t.Errorf("MatchCorruptSalt_NoErr: %w", err)
	}
	if _, ok := err.(base64.CorruptInputError); !ok {
		t.Errorf("MatchCorruptSalt_WrongErr: %T", err)
	}
}

func TestHasherInitStringExprInvalidChar(t *testing.T) {
	_, err := NewHasherFromString(settingArgon2IDExprInvalidType)
	if err == nil {
		t.Errorf("ExprInvalidChar_NoErr: %w", err)
	}
	if _, ok := err.(*ErrUnsupportedExpr); !ok {
		t.Errorf("ExprInvalidChar_WrongErr: %T", err)
	}
}

func TestHasherInitStringExprInvalidBin(t *testing.T) {
	_, err := NewHasherFromString(settingArgon2IDExprInvalidBin)
	if err == nil {
		t.Errorf("ExprInvalidBin_NoErr: %w", err)
	}
	if _, ok := err.(*ErrUnsupportedExpr); !ok {
		t.Errorf("ExprInvalidBin_WrongErr: %T", err)
	}
}

func TestHasherInitStringExprInvalidSigned(t *testing.T) {
	_, err := NewHasherFromString(settingArgon2IDExprInvalidSigned)
	if err == nil {
		t.Errorf("ExprInvalidSigned_NoErr: %w", err)
	}
	if _, ok := err.(*ErrUnsupportedExpr); !ok {
		t.Errorf("ExprInvalidSigned_WrongErr: %T", err)
	}
}

func TestHasherInitStringExprInvalidMax(t *testing.T) {
	_, err := NewHasherFromString(settingArgon2IDExprInvalidMax)
	if err == nil {
		t.Errorf("ExprInvalidMax_NoErr: %w", err)
	}
	if _, ok := err.(*strconv.NumError); !ok {
		t.Errorf("ExprInvalidMax_WrongErr: %T", err)
	}
}

func TestHasherInitStringIDExpr(t *testing.T) {
	hasher, err := NewHasherFromString(settingArgon2IDExpr)
	if err != nil {
		t.Errorf("Init_ID_Expr: %w", err)
	}
	createComparePasswords(t, hasher)
}

func TestHasherInitConfigI(t *testing.T) {
	hasher := &Hasher{
		Form:        FormI,
		SaltLength:  16,
		KeyLength:   32,
		Memory:      65536,
		Iterations:  3,
		Parallelism: 2,
	}
	createComparePasswords(t, hasher)
}

func TestHasherInitConfigID(t *testing.T) {
	hasher := &Hasher{
		Form:        FormID,
		SaltLength:  16,
		KeyLength:   32,
		Memory:      65536,
		Iterations:  3,
		Parallelism: 2,
	}
	createComparePasswords(t, hasher)
}

func TestHasherInitStringD(t *testing.T) {
	_, err := NewHasherFromString(settingArgon2D)
	if err == nil {
		t.Errorf("Init_D: %w", err)
	}
	if _, ok := err.(*ErrInvalidForm); !ok {
		t.Errorf("Init_D_WrongErr: %T", err)
	}
}

func TestHasherInitStringI(t *testing.T) {
	hasher, err := NewHasherFromString(settingArgon2I)
	if err != nil {
		t.Errorf("Init_I: %w", err)
	}
	createComparePasswords(t, hasher)
}

func TestHasherInitStringID(t *testing.T) {
	hasher, err := NewHasherFromString(settingArgon2ID)
	if err != nil {
		t.Errorf("Init_ID: %w", err)
	}
	createComparePasswords(t, hasher)
}

func createComparePasswords(t *testing.T, h *Hasher) {
	hash, err := h.Create(password)
	if err != nil {
		t.Errorf("Create: %w", err)
	}

	ok, err := Matches(password, hash)
	if err != nil {
		t.Errorf("Compare_Init_Correct: %w", err)
	}
	if !ok {
		t.Errorf("Compare_Correct_Pass: %w", err)
	}

	ok, err = Matches(wrongPassword, hash)
	if err != nil {
		t.Errorf("Compare_Init_Incorrect: %w", err)
	}
	if ok {
		t.Errorf("Compare_Incorrect_Pass: %w", err)
	}
}

func ExampleNewHasherFromString() {
	hasherConfig := "f=argon2i,s=16,k=32,m=65536,t=3,p=2"
	hasher, _ := NewHasherFromString(hasherConfig)
	hash, _ := hasher.Create("mySecretPassword")
	fmt.Println(hash)
	// $argon2i$v=19$m=65536,t=3,p=2$oOT8PmX+YLmj8wRveAP0Cg$uIP1h5Z1DOSx9YBBSWOHE84AYGxC9/GwnB3ZFGZFh8E
}

func ExampleNewHasherFromString_memoryExpression() {
	// Mathematical expressions for memory are parsed
	_ = "f=argon2i,s=16,k=32,m=64*1024,t=3,p=2"

	// +, -, *, /, (, ), and space (` `)
	// are the only valid non-numeric symbols.
	_ = "f=argon2i,s=16,k=32,m=((64*1024) + (20-10))/2,t=3,p=2"
}
