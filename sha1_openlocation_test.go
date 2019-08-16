package memdigest_test

import (
	"github.com/reiver/go-memdigest"

	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"

	"testing"
)

func TestSHA1OpenLocation(t *testing.T) {

	tests := []struct{
		Data []struct{
			Content string
			Expected string
			ExpectedLocation string
		}
	}{
		{
			Data: []struct{
				Content string
				Expected string
				ExpectedLocation string
			}{
				{
					Content: "Hello world!",
					Expected: "d3486ae9136e7856bc42212385ea797094475802",
					ExpectedLocation: "memdigest:sha-1:hexadecimal(d3486ae9136e7856bc42212385ea797094475802)/0",
				},
				{
					Content: "😏😐👾🤖😈",
					Expected: "1af2b71ae04ddb01cc36cc615e64c950a50b04ff",
					ExpectedLocation: "memdigest:sha-1:hexadecimal(1af2b71ae04ddb01cc36cc615e64c950a50b04ff)/0",
				},
				{
					Content: "ا ب پ ت ث ج چ ح خ د ذ ر ز ژ س ش ص ض ط ظ ع غ ف ق ک گ ل م ن و ه ی",
					Expected: "8d92165a331ad6ba8ed1ad40507daf1122ce9830",
					ExpectedLocation: "memdigest:sha-1:hexadecimal(8d92165a331ad6ba8ed1ad40507daf1122ce9830)/0",
				},
			},
		},
		{
			Data: []struct{
				Content string
				Expected string
				ExpectedLocation string
			}{

				{
					Content: "apple",
					Expected: "d0be2dc421be4fcd0172e5afceea3970e2f3d940",
					ExpectedLocation: "memdigest:sha-1:hexadecimal(d0be2dc421be4fcd0172e5afceea3970e2f3d940)/0",
				},
				{
					Content: "BANANA",
					Expected: "467b410f79bfca07dcd16fe38e3497c3f6d2db2b",
					ExpectedLocation: "memdigest:sha-1:hexadecimal(467b410f79bfca07dcd16fe38e3497c3f6d2db2b)/0",
				},
				{
					Content: "Cherry",
					Expected: "d6eee90533dffc1f8e6622f9f09af16ed051bf48",
					ExpectedLocation: "memdigest:sha-1:hexadecimal(d6eee90533dffc1f8e6622f9f09af16ed051bf48)/0",
				},
				{
					Content: "dATE",
					Expected: "408ac259233f1b4f6aef295f7d4a7c43d61fb922",
					ExpectedLocation: "memdigest:sha-1:hexadecimal(408ac259233f1b4f6aef295f7d4a7c43d61fb922)/0",
				},
			},
		},
	}

	for testNumber, test := range tests {

		var mem memdigest.SHA1

		for testDatumNumber, testDatum := range test.Data {
			digest, err := mem.Store([]byte(testDatum.Content))
			if nil != err {
				t.Errorf("For test #%d and datum #%d, did not expect an error, but actually got one: (%T) %q", testNumber, testDatumNumber, err, err)
				continue
			}

			expectedDigest, err := hex.DecodeString(testDatum.Expected)
			if nil != err {
				t.Errorf("For test #%d and datum #%d, did not expect an error, but actually got one: (%T) %q", testNumber, testDatumNumber, err, err)
				continue
			}

			if expected, actual := expectedDigest, digest[:]; !bytes.Equal(expected, actual) {
				t.Errorf("For test #%d and datum #%d, the actual digest of content is not what was expected.", testNumber, testDatumNumber)
				t.Logf("Content: %q", testDatum.Content)
				t.Logf("EXPECTED: %q", expected)
				t.Logf("ACTUAL:   %q", actual)
				continue
			}
		}

		for testDatumNumber, testDatum := range test.Data {

			content, err := mem.OpenLocation(testDatum.ExpectedLocation)
			if nil != err {
				t.Errorf("For test #%d and datum #%d, did not expect an error, but actually got one: (%T) %q", testNumber, testDatumNumber, err, err)
				t.Logf("Content: %q", testDatum.Content)
				t.Logf("Digest: %q (hexadecimal)", testDatum.Expected)
				t.Logf("Location: %q", testDatum.ExpectedLocation)
				continue
			}
			if nil == content {
				t.Errorf("For test #%d and datum #%d, expected non-nill content, but did not actually get that: #%v", testNumber, testDatumNumber, content)
				t.Logf("Content: %q", testDatum.Content)
				t.Logf("Digest: %q (hexadecimal)", testDatum.Expected)
				t.Logf("Location: %q", testDatum.ExpectedLocation)
				continue
			}

			{
				r := io.NewSectionReader(content, 0, int64(content.Len()))

				contentBytes, err := ioutil.ReadAll(r)
				if nil != err {
					t.Errorf("For test #%d and datum #%d, did not expect an error, but actually got one: (%T) %q", testNumber, testDatumNumber, err, err)
					t.Logf("Content: %q", testDatum.Content)
					t.Logf("Digest: %q (hexadecimal)", testDatum.Expected)
					t.Logf("Location: %q", testDatum.ExpectedLocation)
					continue
				}
				if expected, actual := testDatum.Content, string(contentBytes); expected != actual {
					t.Errorf("For test #%d and datum #%d, the actual content was not what was expected.", testNumber, testDatumNumber)
					t.Errorf("EXPECTED: %q", expected)
					t.Errorf("ACTUAL:   %q", actual)
					continue
				}
			}
		}
	}
}
