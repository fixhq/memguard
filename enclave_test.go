package memguard

import (
	"bytes"
	"sync"
	"testing"

	"github.com/fixhq/memguard/core"
)

func TestNewEnclave(t *testing.T) {
	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}
	data, err := e.Open()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(data.Bytes(), []byte("yellow submarine")) {
		t.Error("data doesn't match input")
	}
	data.Destroy()
	e = NewEnclave([]byte{})
	if e != nil {
		t.Error("enclave should be nil")
	}
}

func TestNewEnclaveRandom(t *testing.T) {
	e := NewEnclaveRandom(32)
	if e == nil {
		t.Fatal("got nil enclave")
	}
	data, err := e.Open()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(data.Bytes()) != 32 || cap(data.Bytes()) != 32 {
		t.Error("buffer sizes incorrect")
	}
	if bytes.Equal(data.Bytes(), make([]byte, 32)) {
		t.Error("buffer not randomised")
	}
	data.Destroy()
	e = NewEnclaveRandom(0)
	if e != nil {
		t.Error("should be nil")
	}
}

func TestOpen(t *testing.T) {
	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}
	b, err := e.Open()
	if err != nil {
		t.Fatal("unexpected error;", err)
	}
	if b == nil {
		t.Error("buffer should not be nil")
	}
	if e.Size() != b.Size() {
		t.Error("sizes don't match")
	}
	if !bytes.Equal(b.Bytes(), []byte("yellow submarine")) {
		t.Error("data does not match")
	}
	Purge() // reset the session
	b, err = e.Open()
	if err != core.ErrDecryptionFailed {
		t.Error("expected decryption error; got", err)
	}
	if b != nil {
		t.Error("buffer should be nil")
	}
	e = NewEnclaveRandom(0)
	if !panics(func() {
		_, _ = e.Open()
	}) {
		t.Error("func should panic on nil enclave")
	}
}

func TestEnclaveWipe(t *testing.T) {
	e := NewEnclave([]byte("yellow submarine"))
	if e == nil {
		t.Fatal("got nil enclave")
	}
	e.Wipe()
	if e.Size() != 0 {
		t.Error("expected zero size; got", e.Size())
	}

	// Opening a wiped enclave returns an error instead of panicking.
	b, err := e.Open()
	if err != core.ErrEnclaveExpired {
		t.Error("expected ErrEnclaveExpired; got", err)
	}
	if b != nil {
		t.Error("buffer should be nil")
	}

	// Wiping twice, or wiping nil, is fine.
	e.Wipe()
	var n *Enclave
	n.Wipe()
	if n.Size() != 0 {
		t.Error("nil enclave should have zero size")
	}
}

func TestEnclaveWipeConcurrent(t *testing.T) {
	data := []byte("yellow submarine")
	for i := 0; i < 100; i++ {
		e := NewEnclave(bytes.Clone(data))
		if e == nil {
			t.Fatal("got nil enclave")
		}

		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Each reader gets either the plaintext or a clean error.
				b, err := e.Open()
				if err != nil {
					if err != core.ErrEnclaveExpired {
						t.Error("unexpected error:", err)
					}
					return
				}
				defer b.Destroy()
				if !bytes.Equal(b.Bytes(), data) {
					t.Error("data does not match")
				}
			}()
		}
		for j := 0; j < 2; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.Wipe()
			}()
		}
		wg.Wait()

		if _, err := e.Open(); err != core.ErrEnclaveExpired {
			t.Fatal("expected ErrEnclaveExpired; got", err)
		}
	}
}

func panics(fn func()) (panicked bool) {
	defer func() {
		panicked = (recover() != nil)
	}()
	fn()
	return
}
