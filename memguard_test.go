package memguard

import (
	"bytes"
	"testing"

	"github.com/fixhq/memguard/core"
)

func TestScrambleBytes(t *testing.T) {
	buf := make([]byte, 32)
	ScrambleBytes(buf)
	if bytes.Equal(buf, make([]byte, 32)) {
		t.Error("buffer not scrambled")
	}
}

func TestWipeBytes(t *testing.T) {
	buf := make([]byte, 32)
	ScrambleBytes(buf)
	WipeBytes(buf)
	if !bytes.Equal(buf, make([]byte, 32)) {
		t.Error("buffer not wiped")
	}
}

func TestPurge(t *testing.T) {
	key := NewEnclaveRandom(32)
	if key == nil {
		t.Fatal("NewEnclaveRandom returned nil")
	}
	buf, err := key.Open()
	if err != nil {
		t.Fatal(err)
	}
	Purge()
	if buf.IsAlive() {
		t.Error("buffer not destroyed")
	}
	buf, err = key.Open()
	if err != core.ErrDecryptionFailed {
		if buf != nil {
			t.Error(buf.Bytes(), err)
		} else {
			t.Error("unexpected error:", err)
		}
	}
	if buf != nil {
		t.Error("buffer not nil:", buf)
	}
}
