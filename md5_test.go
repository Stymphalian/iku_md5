package md5

import (
	"bytes"
	"io"
	"testing"
)

func convertMsgToByteArray(msg [16]uint32) []byte {
	gotBytes := make([]byte, 0)
	for _, v := range msg {
		gotBytes = append(gotBytes, byte((v >> 0)))
		gotBytes = append(gotBytes, byte((v >> 8)))
		gotBytes = append(gotBytes, byte((v >> 16)))
		gotBytes = append(gotBytes, byte((v >> 24)))
	}
	return gotBytes
}

func TestMd5Reader_GetMessage(t *testing.T) {
	// The byte buffer is exactly 64 bytes longs (exactly 512 bits)
	wantBytes := []byte(
		"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
	)
	buf := bytes.NewBuffer(wantBytes)
	r, err := newMd5Reader(buf)
	if err != nil {
		t.Errorf("Failed to md5Reader: %v", err)
	}
	v, err := r.GetMessage()
	if err != nil {
		t.Errorf("Failed to GetMessage, %v", err)
	}

	// 1. We should be able to retrieve the bytes message, all in the same order
	gotBytes := convertMsgToByteArray(v)
	if bytes.Compare(gotBytes, wantBytes) != 0 {
		t.Errorf("Did not get correct bytes:\ngotBytes : %x\nwantBytes: %x\n", gotBytes, wantBytes)
	}

	// 2. Creatinga new reader should have added padding bits, retrieve this now
	//    and make sure it is as we expected.
	v, err = r.GetMessage()
	if err != nil {
		t.Errorf("Failed to GetMessage, %v", err)
	}
	gotBytes = convertMsgToByteArray(v)
	wantBytes = []byte{
		// The first byte here is the 1 bit added to the bit stream
		0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// These last two bytes contain the length, little endian encoded
		0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	if bytes.Compare(gotBytes, wantBytes) != 0 {
		t.Errorf("Did not get correct bytes:\ngotBytes : %x\nwantBytes: %x\n", gotBytes, wantBytes)
	}

	// The last read should return EOF
	_, err = r.GetMessage()
	if err != io.EOF {
		t.Errorf("Should have returned EOF once no more data in buffer but got %v", err)
	}
}

func TestMd5(t *testing.T) {
	testCases := []struct {
		input    string
		wantHash string
	}{
		{
			// Empty
			"",
			"d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			// length 1 bytes length
			"a",
			"0cc175b9c0f1b6a831c399e269772661",
		},
		{
			// input just reaches 512 bit length
			"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
			"386f81fd57366030ae7ea0392a2c87ae",
		},
		{
			// input is less than 512 bit length
			"abcdabcdabcdabcdabcdabcdabcdabcdabcd",
			"768f019d65e525d078ed2ef5e97ed885",
		},
		{
			// input is one less than 512 bit length
			"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc",
			"62c655e4702b8ca14aaac22ab06fdc3f",
		},
		{
			// input is one over the 512 bit length
			"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcda",
			"d4fe9566b8846c3c96f3514008579521",
		},
		{
			// input is much over the 512 bit length
			"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" +
				"abcdabcdabcdabcdabcdabcdabcdabcdabcd",
			"762d87e69334c61f755da9d24d5a1875",
		},
		{
			// input is 512*2 bits longs
			"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" +
				"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
			"f0589c0fa8745d8d2061b00d02ac5e5b",
		},
		// Random test inputs
		{
			"abc",
			"900150983cd24fb0d6963f7d28e17f72",
		},
		{
			"abcdefghijklmnopqrstuvwxyz",
			"c3fcd3d76192e4007dfb496cca67e13b",
		},
		{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"d174ab98d277d9f5a5611c2c9f419d9f",
		},
	}

	for i, tc := range testCases {
		b := bytes.NewBufferString(tc.input)
		gotHash, err := Md5(b)
		if err != nil {
			t.Errorf("Failed to compute md5 %v", err)
			return
		}
		if gotHash != tc.wantHash {
			t.Errorf("[%d] hash mismatch: \ngotHash  = '%s'\nwantHash = '%s'", i, gotHash, tc.wantHash)
		}
	}

}
