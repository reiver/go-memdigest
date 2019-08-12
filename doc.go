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
	// digest    == "70cc03f611f457342c7bf69e7bd3ca0eabf17d75"
	algorithm, digest, err := mountpoint.Create([]byte("The request has been accepted for processing, but the processing has not been completed."))
	
	// ...
	
	// algorithm == "SHA-1"
	// digest    == "f58802bc6adbe90281759682fbcfed6045b03a26"
	algorithm, digest, err := mountpoint.Create([]byte("The server has fulfilled the request but does not need to return an entity-body, and might want to return updated metainformation."))
	
	// ...
	
	// algorithm == "SHA-1"
	// digest    == "59d4cf28c9831ade812e9ba3919040baedea9266"
	algorithm, digest, err := mountpoint.Create([]byte("The server encountered an unexpected condition which prevented it from fulfilling the request."))
	
	// ...
	
	content, err := mountpoint.Open("SHA-1", "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a")
	if nil != err {
		return err
	}
	defer content.Close()

The reason why one would use memdigest through digestfs, rather than use memdigest directly, is because so that
memdigest could be swapped out with another content-addressable storage (CAS), or combined with another
content-addressable storage (CAS), and code using digestfs would (almost completely) remain the same.
*/
package memdigest
