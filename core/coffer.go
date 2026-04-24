package core

import (
	"errors"
	"sync"
	"time"
)

// Interval of time between each verify & re-key cycle.
const interval = 500 * time.Millisecond

// ErrCofferExpired is returned when a function attempts to perform an operation using a secure key container that has been wiped and destroyed.
var ErrCofferExpired = errors.New("<memguard::core::ErrCofferExpired> attempted usage of destroyed key object")

/*
Coffer is a specialized container for securing highly-sensitive, 32 byte values.
*/
type Coffer struct {
	left  *Buffer
	right *Buffer
	rand  *Buffer
	done  chan struct{}
	sync.Mutex
}

// NewCoffer is a raw constructor for the *Coffer object.
func NewCoffer() *Coffer {
	s := new(Coffer)
	s.left, _ = NewBuffer(32)
	s.right, _ = NewBuffer(32)
	s.rand, _ = NewBuffer(32)

	s.done = make(chan struct{})
	if err := s.Init(); err != nil {
		Panic(err)
	}

	go func(s *Coffer) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				if err := s.Rekey(); err != nil {
					return
				}
			}
		}
	}(s)

	return s
}

// Init is used to reset the value stored inside a Coffer to a new random 32 byte value, overwriting the old.
func (s *Coffer) Init() error {
	s.Lock()
	defer s.Unlock()
	if s.destroyed() {
		return ErrCofferExpired
	}

	if err := Scramble(s.left.Data()); err != nil {
		return err
	}
	if err := Scramble(s.right.Data()); err != nil {
		return err
	}

	// left = left XOR hash(right)
	hr := Hash(s.right.Data())
	for i := range hr {
		s.left.Data()[i] ^= hr[i]
	}
	Wipe(hr)

	return nil
}

/*
View returns a snapshot of the contents of a Coffer inside a Buffer. As usual the Buffer should be destroyed as soon as possible after use by calling the Destroy method.
*/
func (s *Coffer) View() (*Buffer, error) {
	s.Lock()
	defer s.Unlock()
	if s.destroyed() {
		return nil, ErrCofferExpired
	}
	b, err := NewBuffer(32)
	if err != nil {
		return nil, err
	}

	// data = hash(right) XOR left
	h := Hash(s.right.Data())

	for i := range b.Data() {
		b.Data()[i] = h[i] ^ s.left.Data()[i]
	}
	Wipe(h)

	return b, nil
}

/*
Rekey is used to re-key a Coffer. Ideally this should be done at short, regular intervals.
*/
func (s *Coffer) Rekey() error {
	s.Lock()
	defer s.Unlock()
	if s.destroyed() {
		return ErrCofferExpired
	}

	if err := Scramble(s.rand.Data()); err != nil {
		return err
	}

	// Hash the current right partition for later.
	hashRightCurrent := Hash(s.right.Data())

	// new_right = current_right XOR buf32
	for i := range s.right.Data() {
		s.right.Data()[i] ^= s.rand.Data()[i]
	}

	// new_left = current_left XOR hash(current_right) XOR hash(new_right)
	hashRightNew := Hash(s.right.Data())
	for i := range s.left.Data() {
		s.left.Data()[i] ^= hashRightCurrent[i] ^ hashRightNew[i]
	}
	Wipe(hashRightNew)
	Wipe(hashRightCurrent)

	return nil
}

/*
Destroy wipes and cleans up all memory related to a Coffer object. Once this method has been called, the Coffer can no longer be used and a new one should be created instead.
*/
func (s *Coffer) Destroy() error {
	s.Lock()
	defer s.Unlock()

	// Signal the re-key goroutine to stop.
	if s.done != nil {
		select {
		case <-s.done:
			// Already closed.
		default:
			close(s.done)
		}
	}

	err1 := s.left.destroy()
	if err1 == nil {
		buffers.remove(s.left)
	}
	err2 := s.right.destroy()
	if err2 == nil {
		buffers.remove(s.right)
	}
	err3 := s.rand.destroy()
	if err3 == nil {
		buffers.remove(s.rand)
	}

	errS := ""
	if err1 != nil {
		errS = errS + err1.Error() + "\n"
	}
	if err2 != nil {
		errS = errS + err2.Error() + "\n"
	}
	if err3 != nil {
		errS = errS + err3.Error() + "\n"
	}
	if errS == "" {
		return nil
	}
	return errors.New(errS)
}

// Destroyed returns a boolean value indicating if a Coffer has been destroyed.
func (s *Coffer) Destroyed() bool {
	if s == nil {
		return true
	}

	s.Lock()
	defer s.Unlock()

	return s.destroyed()
}

func (s *Coffer) destroyed() bool {
	if s.left == nil || s.right == nil {
		return true
	}

	return s.left.isDestroyed() || s.right.isDestroyed()
}
