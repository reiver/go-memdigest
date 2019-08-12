package memdigest

import (
	"github.com/reiver/go-digestfs/driver"

	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

const (
	algorithmSHA1 string = "SHA-1"
)

func init() {
	const name string = "memdigest.SHA1"

	var mounter digestfs_driver.Mounter = digestfs_driver.MounterFunc(func(args ...interface{}) (digestfs_driver.MountPoint, error){
		if expected, actual := 1, len(args); expected != actual {
			return nil, fmt.Errorf("memdigest: Wrong Number Of Arguments: expected %d, but actually got %d", expected, actual)
		}

		arg0 := args[0]

		mem, casted := arg0.(*SHA1)
		if !casted {
			return nil, fmt.Errorf("memdigest: Wrong Type: expected *memdigest.SHA1, but actually got %T", arg0)
		}

		return mem, nil
	})

	digestfs_driver.Registry.Register(mounter, name)
}

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

func (receiver *SHA1) Open(algorithm string, digest string) (digestfs_driver.Content, error) {
	if nil == receiver {
		return nil, digestfs_driver.ErrContentNotFound(algorithm, digest)
	}

	if algorithmSHA1 != algorithm {
		return nil, digestfs_driver.ErrUnsupportedAlgorithm(algorithm)
	}

	binaryDigest, err := hex.DecodeString(digest)
	if nil != err {
		return nil, digestfs_driver.ErrContentNotFound(algorithm, digest)
	}

	if sha1.Size != len(binaryDigest) {
		return nil, digestfs_driver.ErrContentNotFound(algorithm, digest)
	}

	value, found := receiver.Load(binaryDigest)
	if !found {
		return nil, digestfs_driver.ErrContentNotFound(algorithm, digest)
	}

	return digestfs_driver.StringContent(value), nil
}

// OpenLocation makes *memdigest.SHA1 fit the digestfs_driver.MountPoint interface.
func (receiver *SHA1) OpenLocation(location string) (digestfs_driver.Content, error) {
	const prefix string = "@^"
	if !strings.HasPrefix(location, prefix) {
		return nil, digestfs_driver.ErrBadLocation(location)
	}
	digest := location[len(prefix):]

	return receiver.Open(algorithmSHA1, digest)
}

// Store stores ‘content’ and returns the SHA-1 digest of ‘content’.
//
// Example
//
// Here is an example of it being used:
//
//	var mem *memdigest.SHA1
//	
//	// ...
//	
//	var content []byte = []byte("The request has been fulfilled and resulted in a new resource being created.")
//	
//	// ...
//	
//	digest, err := mem.Store(content)
//
// The returned digest is in binary form, not hexadecimal.
//
// In the case of our example, it will be:
//
//	[64]byte{0x0c, 0xe9, 0xff, 0x3b, 0x12, 0xaf, 0xdb, 0x31, 0x61, 0x75, 0x1e, 0x3a, 0xb4, 0x49, 0x87, 0x62, 0x95, 0x23, 0x63, 0x3d}
//
// If you want to convert it to hexadecimal, you can do so with code such as:
//
//	hexadecimalDigest := fmt.Sprintf("%x", digest)
//
// Which will return the string:
//
//	"0ce9ff3b12afdb3161751e3ab44987629523633d"
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
