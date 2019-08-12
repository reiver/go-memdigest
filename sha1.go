package memdigest

import (
	"github.com/reiver/go-digestfs/driver"

	"crypto/sha1"
	"strings"
	"sync"
)

type SHA1 struct {
	mutex sync.RWMutex
	data map[[sha1.Size]byte]string
}

func (receiver *SHA1) Load(digest []byte) (string, bool) {
	if nil == receiver {
		return "", false
	}

	if sha1.Size != len(digest) {
		return "", false
	}

	receiver.mutex.RLock()
	defer receiver.mutex.RUnlock()

	data := receiver.data
	if nil == data {
		return "", false
	}

	var key [sha1.Size]byte
	copy(key[:], digest)

	value, found := data[key]
	if !found {
		return "", false
	}

	return value, true
}

func (receiver *SHA1) Open(algorithm string, digest []byte) (digestfs_driver.Content, error) {
	if nil == receiver {
		return nil, digestfs_driver.ErrContentNotFound(algorithm, digest)
	}

	if "SHA-1" != algorithm {
		return nil, digestfs_driver.ErrUnsupportedAlgorithm(algorithm)
	}

	if sha1.Size != len(digest) {
		return nil, digestfs_driver.ErrContentNotFound(algorithm, digest)
	}

	value, found := receiver.Load(digest)
	if !found {
		return nil, digestfs_driver.ErrContentNotFound(algorithm, digest)
	}

	return digestfs_driver.StringContent(value), nil
}

func (receiver *SHA1) OpenLocation(location string) (digestfs_driver.Content, error) {
	const prefix string = "@^"
	if !strings.HasPrefix(location, prefix) {
		return nil, digestfs_driver.ErrBadLocation(location)
	}
	digest := location[len(prefix):]

	return receiver.Open("SHA-1", []byte(digest))
}

func (receiver *SHA1) Store(content []byte) ([sha1.Size]byte, error) {
	if nil == receiver {
		return [sha1.Size]byte{}, errNilReceiver
	}

	receiver.mutex.Lock()
	defer receiver.mutex.Unlock()

	if nil == receiver.data {
		receiver.data = map[[sha1.Size]byte]string{}
	}

	key := sha1.Sum(content)

	receiver.data[key] = string(content)

	return key, nil
}

// Unmount makes *memdigest.SHA1 fit the digestfs_driver.MountPoint interface.
//
// Unmount will never return an error, but will (conceptually) removed all content it was previously storing.
//
// Example
//
// Here is an example of it being used:
//
//	var mem *memdigest.SHA1
//	
//	// ...
//	
//	err := mem.Unmount()
func (receiver *SHA1) Unmount() error {
	if nil == receiver {
		return nil
	}

	receiver.mutex.Lock()
	defer receiver.mutex.Unlock()

	receiver.data = nil

	return nil
}
