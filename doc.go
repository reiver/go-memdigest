/*
Package memdigest provides an in memory content-addressable storage (CAS),
and can be used as a CAS for the digestfs (https://github.com/reiver/go-digestfs) content-addressable virtual file system (VFS).

Example

Package memdigest can be used via digestfs.
For example:

	import (
		"github.com/reiver/go-digestfs"
		"github.com/reiver/go-memdigest"
	)
	
	// ...
	
	var mem memdigest.SHA1
	
	// ...
	
	var mountpoint digestfs.MountPoint
	
	err := mountpoint.Mount("memdigest.SHA1", &mem)
	
	// ...
	
	// algorithm == "SHA-1"
	// digest    == "\x70\xcc\x03\xf6\x11\xf4\x57\x34\x2c\x7b\xf6\x9e\x7b\xd3\xca\x0e\xab\xf1\x7d\x75" // 0x70cc03f611f457342c7bf69e7bd3ca0eabf17d75
	algorithm, digest, err := mountpoint.Create([]byte("The request has been accepted for processing, but the processing has not been completed."))
	
	// ...
	
	// algorithm == "SHA-1"
	// digest    == "\xf5\x88\x02\xbc\x6a\xdb\xe9\x02\x81\x75\x96\x82\xfb\xcf\xed\x60\x45\xb0\x3a\x26" // 0xf58802bc6adbe90281759682fbcfed6045b03a26
	algorithm, digest, err := mountpoint.Create([]byte("The server has fulfilled the request but does not need to return an entity-body, and might want to return updated metainformation."))
	
	// ...
	
	// algorithm == "SHA-1"
	// digest    == "\x59\xd4\xcf\x28\xc9\x83\x1a\xde\x81\x2e\x9b\xa3\x91\x90\x40\xba\xed\xea\x92\x66" // 0x59d4cf28c9831ade812e9ba3919040baedea9266
	algorithm, digest, err := mountpoint.Create([]byte("The server encountered an unexpected condition which prevented it from fulfilling the request."))
	
	// ...
	
	content, err := mountpoint.Open("SHA-1", "\xc0\x53\x5e\x4b\xe2\xb7\x9f\xfd\x93\x29\x13\x05\x43\x6b\xf8\x89\x31\x4e\x4a\x3f\xae\xc0\x5e\xcf\xfc\xbb\x7d\xf3\x1a\xd9\xe5\x1a") // 0xc0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a
	if nil != err {
		return err
	}
	defer content.Close()

The reason why one would use memdigest through digestfs, rather than use memdigest directly, is because so that
memdigest could be swapped out with another content-addressable storage (CAS), or combined with another
content-addressable storage (CAS), and code using digestfs would (almost completely) remain the same.
*/
package memdigest
