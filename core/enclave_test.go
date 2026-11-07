package core

import (
	"bytes"
	"testing"
)

func TestNewEnclave(t *testing.T) {
	// Initialise some sample plaintext.
	data := []byte("yellow submarine")

	// Create the Enclave object from this data.
	e, err := NewEnclave(data)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the buffer has been wiped.
	if !bytes.Equal(data, make([]byte, 16)) {
		t.Error("data buffer was not wiped")
	}

	// Verify the length of the ciphertext is correct.
	if len(e.ciphertext) != len(data)+Overhead {
		t.Error("ciphertext has unexpected length;", len(e.ciphertext))
	}

	// Attempt with an empty data slice.
	data = make([]byte, 0)
	_, err = NewEnclave(data)
	if err != ErrNullEnclave {
		t.Error("expected ErrNullEnclave; got", err)
	}
}

func TestSeal(t *testing.T) {
	// Create a new buffer for testing with.
	b, err := NewBuffer(32)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt it into an Enclave.
	e, err := Seal(b)
	if err != nil {
		t.Fatal(err)
	}

	// Do a sanity check on the length of the ciphertext.
	if len(e.ciphertext) != 32+Overhead {
		t.Error("ciphertext has unexpected length:", len(e.ciphertext))
	}

	// Check that the buffer was destroyed.
	if b.alive {
		t.Error("buffer was not consumed")
	}

	// Decrypt the enclave into a new buffer.
	buf, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the decrypted data is correct.
	if !bytes.Equal(buf.Data(), make([]byte, 32)) {
		t.Error("decrypted data does not match original")
	}

	// Attempt sealing the destroyed buffer.
	e, err = Seal(b)
	if err != ErrBufferExpired {
		t.Error("expected ErrBufferExpired; got", err)
	}
	if e != nil {
		t.Error("expected nil enclave in error case")
	}

	// Destroy the hanging buffer.
	buf.Destroy()
}

func TestOpen(t *testing.T) {
	// Initialise an enclave to test on.
	data := []byte("yellow submarine")
	e, err := NewEnclave(data)
	if err != nil {
		t.Fatal(err)
	}

	// Open it.
	buf, err := Open(e)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity check the output.
	if !bytes.Equal(buf.Data(), []byte("yellow submarine")) {
		t.Error("decrypted data does not match original")
	}
	buf.Destroy()

	// Modify the ciphertext to trigger an error case.
	for i := range e.ciphertext {
		e.ciphertext[i] = 0xdb
	}

	// Check for the error.
	buf, err = Open(e)
	if err != ErrDecryptionFailed {
		t.Error("expected decryption error; got", err)
	}
	if buf != nil {
		t.Error("expected nil buffer in error case")
	}
}

func TestEnclaveSize(t *testing.T) {
	if EnclaveSize(&Enclave{ciphertext: make([]byte, 1234)}) != 1234-Overhead {
		t.Error("invalid enclave size")
	}
	if EnclaveSize(nil) != 0 {
		t.Error("nil enclave should have zero size")
	}
}

func TestWipeEnclave(t *testing.T) {
	e, err := NewEnclave([]byte("yellow submarine"))
	if err != nil {
		t.Fatal(err)
	}

	// Keep a reference to the backing array so we can inspect it after the wipe.
	ciphertext := e.ciphertext
	if bytes.Equal(ciphertext, make([]byte, len(ciphertext))) {
		t.Fatal("ciphertext is zero before wipe")
	}

	WipeEnclave(e)

	// Check that the ciphertext was zeroed in place and released.
	if !bytes.Equal(ciphertext, make([]byte, len(ciphertext))) {
		t.Error("ciphertext was not wiped")
	}
	if e.ciphertext != nil {
		t.Error("ciphertext was not released")
	}
	if EnclaveSize(e) != 0 {
		t.Error("expected zero size; got", EnclaveSize(e))
	}

	// Opening a wiped enclave must fail cleanly.
	buf, err := Open(e)
	if err != ErrEnclaveExpired {
		t.Error("expected ErrEnclaveExpired; got", err)
	}
	if buf != nil {
		t.Error("expected nil buffer in error case")
	}

	// Wiping again, or wiping nil, is a no-op.
	WipeEnclave(e)
	WipeEnclave(nil)
	if _, err := Open(e); err != ErrEnclaveExpired {
		t.Error("expected ErrEnclaveExpired after second wipe; got", err)
	}
}
