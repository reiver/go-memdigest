package memdigest_test

import (
	"github.com/reiver/go-memdigest"

	"github.com/reiver/go-digestfs"

	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"

	"testing"
)

func TestSHA1(t *testing.T) {

	tests := []struct{
		Data []struct{
			Content string
			Expected string
		}
	}{
		{
			Data: []struct{
				Content string
				Expected string
			}{},
		},



		{
			Data: []struct{
				Content string
				Expected string
			}{
				{
					Content: "Hello world!",
					Expected: "d3486ae9136e7856bc42212385ea797094475802",
				},
				{
					Content: "😏😐👾🤖😈",
					Expected: "1af2b71ae04ddb01cc36cc615e64c950a50b04ff",
				},
				{
					Content: "ا ب پ ت ث ج چ ح خ د ذ ر ز ژ س ش ص ض ط ظ ع غ ف ق ک گ ل م ن و ه ی",
					Expected: "8d92165a331ad6ba8ed1ad40507daf1122ce9830",
				},
			},
		},



		{
			Data: []struct{
				Content string
				Expected string
			}{
				{
					Content: "apple",
					Expected: "d0be2dc421be4fcd0172e5afceea3970e2f3d940",
				},
				{
					Content: "BANANA",
					Expected: "467b410f79bfca07dcd16fe38e3497c3f6d2db2b",
				},
				{
					Content: "Cherry",
					Expected: "d6eee90533dffc1f8e6622f9f09af16ed051bf48",
				},
				{
					Content: "dATE",
					Expected: "408ac259233f1b4f6aef295f7d4a7c43d61fb922",
				},
			},
		},
	}

	for testNumber, test := range tests {

		var mem memdigest.SHA1

		{
			nonExistentDigest := [sha1.Size]byte{0x59, 0xdb, 0x6b, 0xa4, 0xa6, 0xaf, 0xf5, 0xed, 0x3d, 0x98, 0x05, 0x42, 0xda, 0xf4, 0x1b, 0xe6, 0x56, 0x24, 0xa1, 0xe8}

			{
				_, found := mem.Load(nonExistentDigest[:])
				if found {
					t.Errorf("For test #%d, did not expect value to exist for the SHA-1 digest.", testNumber)
					t.Logf("SHA-1 digest: %x", nonExistentDigest)
					continue
				}
			}

			{
				content, err := mem.Open("SHA-1", nonExistentDigest[:])
				if nil == err {
					t.Errorf("For test #%d, expected an error, but did not actually get one: %#v", testNumber, err)
					continue
				}
				switch err.(type) {
				case digestfs.ContentNotFound:
					// Nothing here.
				default:
					t.Errorf("For test #%d, expected error to be ContentNotFound, but actually wasn't: (%T) %q", testNumber, err, err)
					continue
				}
				if nil != content {
					t.Errorf("For test #%d, expected nil content, but actually wasn't: %#v", testNumber, content)
					continue
				}
			}
		}

		for testDatumNumber, testDatum := range test.Data {
			actual, err := mem.Store([]byte(testDatum.Content))
			if nil != err {
				t.Errorf("For test #%d and datum #%d, did not expect to get an error, but actually got one: (%T) %q", testNumber, testDatumNumber, err, err)
				continue
			}

			if expected, actual := testDatum.Expected, fmt.Sprintf("%x", actual[:]); expected != actual {
				t.Errorf("For test #%d and datum #%d, the SHA-1that was actually gotten was not what was expected.", testNumber, testDatumNumber)
				t.Logf("EXPECTED: %q", expected)
				t.Logf("ACTUAL:   %q", actual)
				t.Logf("CONTENT: %q", testDatum.Content)
				continue
			}
		}

		for testDatumNumber, testDatum := range test.Data {

			digest, err := hex.DecodeString(testDatum.Expected)
			if nil != err {
				t.Errorf("For test #%d and datum #%d, did not expect an error, but actually got one: (%T) %q", testNumber, testDatumNumber, err, err)
				continue
			}

			{
				value, found := mem.Load(digest)
				if !found {
					t.Errorf("For test #%d and datum #%d, expected value to exist for the SHA-1 digest.", testNumber, testDatumNumber)
					t.Logf("SHA-1 digest: %x", testDatum.Expected)
					continue
				}
				if expected, actual := testDatum.Content, value; expected != actual {
					t.Errorf("For test #%d and datum #%d, the actual value is not what was expected.", testNumber, testDatumNumber)
					t.Logf("EXPECTED: %q", expected)
					t.Logf("ACTUAL:   %q", actual)
					continue
				}
			}

			{
				content, err := mem.Open("SHA-1", digest)
				if nil != err {
					t.Errorf("For test #%d, did not expect an error, but actually got one: (%T) %q", testNumber, err, err)
					continue
				}

				r := io.NewSectionReader(content, 0, int64(content.Len()))
				value, err := ioutil.ReadAll(r)

				if expected, actual := testDatum.Content, string(value); expected != actual {
					t.Errorf("For test #%d and datum #%d, the actual value is not what was expected.", testNumber, testDatumNumber)
					t.Logf("EXPECTED: %q", expected)
					t.Logf("ACTUAL:   %q", actual)
					continue
				}
			}
		}

		{
			nonExistentDigest := [sha1.Size]byte{0x59, 0xdb, 0x6b, 0xa4, 0xa6, 0xaf, 0xf5, 0xed, 0x3d, 0x98, 0x05, 0x42, 0xda, 0xf4, 0x1b, 0xe6, 0x56, 0x24, 0xa1, 0xe8}

			{
				_, found := mem.Load(nonExistentDigest[:])
				if found {
					t.Errorf("For test #%d, did not expect value to exist for the SHA-1 digest.", testNumber)
					t.Logf("SHA-1 digest: %x", nonExistentDigest)
					continue
				}
			}

			{
				content, err := mem.Open("SHA-1", nonExistentDigest[:])
				if nil == err {
					t.Errorf("For test #%d, expected an error, but did not actually get one: %#v", testNumber, err)
					continue
				}
				switch err.(type) {
				case digestfs.ContentNotFound:
					// Nothing here.
				default:
					t.Errorf("For test #%d, expected error to be ContentNotFound, but actually wasn't: (%T) %q", testNumber, err, err)
					continue
				}
				if nil != content {
					t.Errorf("For test #%d, expected nil content, but actually wasn't: %#v", testNumber, content)
					continue
				}
			}
		}

		err := mem.Unmount()
		if nil != err {
			t.Errorf("For test #%d, expected an error, but did not actually get one: %#v", testNumber, err)
			continue
		}

		{
			nonExistentDigest := [sha1.Size]byte{0x59, 0xdb, 0x6b, 0xa4, 0xa6, 0xaf, 0xf5, 0xed, 0x3d, 0x98, 0x05, 0x42, 0xda, 0xf4, 0x1b, 0xe6, 0x56, 0x24, 0xa1, 0xe8}

			{
				_, found := mem.Load(nonExistentDigest[:])
				if found {
					t.Errorf("For test #%d, did not expect value to exist for the SHA-1 digest.", testNumber)
					t.Logf("SHA-1 digest: %x", nonExistentDigest)
					continue
				}
			}

			{
				content, err := mem.Open("SHA-1", nonExistentDigest[:])
				if nil == err {
					t.Errorf("For test #%d, expected an error, but did not actually get one: %#v", testNumber, err)
					continue
				}
				switch err.(type) {
				case digestfs.ContentNotFound:
					// Nothing here.
				default:
					t.Errorf("For test #%d, expected error to be ContentNotFound, but actually wasn't: (%T) %q", testNumber, err, err)
					continue
				}
				if nil != content {
					t.Errorf("For test #%d, expected nil content, but actually wasn't: %#v", testNumber, content)
					continue
				}
			}
		}

		for testDatumNumber, testDatum := range test.Data {

			digest, err := hex.DecodeString(testDatum.Expected)
			if nil != err {
				t.Errorf("For test #%d and datum #%d, did not expect an error, but actually got one: (%T) %q", testNumber, testDatumNumber, err, err)
				continue
			}

			{
				value, found := mem.Load(digest)
				if found {
					t.Errorf("For test #%d and datum #%d, expected value to exist for the SHA-1 digest.", testNumber, testDatumNumber)
					t.Logf("SHA-1 digest: %x", testDatum.Expected)
					t.Logf("Value: %q", value)
					continue
				}
			}

			{
				_, err := mem.Open("SHA-1", digest)
				if nil == err {
					t.Errorf("For test #%d, expected an error, but did not actually get one: %#v", testNumber, err)
					continue
				}
				switch err.(type) {
				case digestfs.ContentNotFound:
					// Nothing here.
				default:
					t.Errorf("For test #%d, expected error to be ContentNotFound, but actually wasn't: (%T) %q", testNumber, err, err)
					continue
				}
			}
		}
	}
}
