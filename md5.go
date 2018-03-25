package md5

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/bits"
)

var (
	KShiftAmounts = [64]uint{
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
	}

	KConstants = [64]uint32{
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
	}

	KA0 = uint32(0x67452301)
	KB0 = uint32(0xefcdab89)
	KC0 = uint32(0x98badcfe)
	KD0 = uint32(0x10325476)
)

// Consts used to keep the current 'state' when we are reading bytes from
// the stream.
const (
	E_READING_BYTES    = iota // Read bytes from the stream
	E_READING_ZEROES   = iota // Return 0 bytes as a part of the paddding
	E_READING_LEN_LOW  = iota // Return bytes from the low word of the length
	E_READING_LEN_HIGH = iota // Return bytes from the high word of the length
	E_READING_END      = iota // The terminating state
)

// Internal reader struct used to read bytes from the stream
type reader struct {
	r           io.Reader
	originalLen uint64
	currentLen  uint64
	numBytes    uint
	state       int
}

func newMd5Reader(r io.Reader) (*reader, error) {
	return &reader{r, 0, 0, 0, E_READING_BYTES}, nil
}

// Return a single byte from the stream, or the padding bytes if we reach the
// end of the stream.
// error will return EOF once there are no more bytes to receive. This includes
// once we have read all thee padding bytes required.
func (this *reader) ReadByte() (byte, error) {
	if this.state == E_READING_BYTES {
		// Read bytes from the reader stream, once we reach EOF then
		// we start returning  0x00 bytes until we reach the right length
		var b byte = 0x00
		err := binary.Read(this.r, binary.LittleEndian, &b)
		if err == io.EOF {
			this.state = E_READING_ZEROES
			this.originalLen = this.currentLen
			// return a single 1 byte to the stream
			b = 0x80
		} else if err != nil {
			return 0x00, err
		}
		this.currentLen += 8
		return b, nil
	} else if this.state == E_READING_ZEROES {
		if this.currentLen%512 == 448 {
			// We have read all the zeroes we need to reach the buffered length
			// so return the low word of the length
			this.state = E_READING_LEN_LOW
			this.numBytes = 1
			return byte(this.originalLen), nil
		} else {
			// Return 0 bytes until we reach the required length
			this.currentLen += 8
			return 0x00, nil
		}
	} else if this.state == E_READING_LEN_LOW {
		// Return the low word of the length.
		this.numBytes += 1
		if this.numBytes == 4 {
			this.state = E_READING_LEN_HIGH
			this.numBytes = 0
		}
		return byte(this.originalLen >> ((this.numBytes - 1) * 8)), nil
	} else if this.state == E_READING_LEN_HIGH {
		// Return the high word of the length. This is the
		this.numBytes += 1
		if this.numBytes == 4 {
			this.state = E_READING_END
		}
		return byte(this.originalLen >> (32 + (this.numBytes-1)*8)), nil

	} else {
		// We are done reading all the bytes we need so just return EOF
		// and reset the state. If the caller calls again this will
		// try to fetch from the reader stream which will probably return
		// an error.
		this.state = E_READING_BYTES
		return 0x00, io.EOF
	}
}

// Return an array of 16 words to be used as the chunk for one round.
// Reads from the  input stream until EOF, then starts adding the requied
// buffering bytes.
func (this *reader) GetMessage() ([16]uint32, error) {
	buf := [16]uint32{}
	for i := 0; i < 16; i++ {
		b1, err := this.ReadByte()
		if err != nil {
			return buf, err
		}
		b2, err := this.ReadByte()
		if err != nil {
			return buf, err
		}
		b3, err := this.ReadByte()
		if err != nil {
			return buf, err
		}
		b4, err := this.ReadByte()
		if err != nil {
			return buf, err
		}
		buf[i] = uint32(b1) | (uint32(b2) << 8) | (uint32(b3) << 16) | (uint32(b4) << 24)
	}
	return buf, nil
}

// Calcualte the Md5 sum given the
func Md5(r io.Reader) (string, error) {
	// Create an internal reader to keep all the state.
	reader, err := newMd5Reader(r)
	if err != nil {
		return "", err
	}

	var prevA, prevB, prevC, prevD uint32
	var A, B, C, D uint32 = KA0, KB0, KC0, KD0
	// Infinite loop through all the input chunks until we are out of input
	for {
		M, err := reader.GetMessage()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		// Process a single chunk
		prevA, prevB, prevC, prevD = A, B, C, D
		for i := uint32(0); i < 64; i++ {
			var F uint32
			var g uint32

			if i >= 0 && i <= 15 {
				// 1st. round
				F = (B & C) | ((^B) & D)
				g = i
			} else if i >= 16 && i <= 31 {
				// 2nd. round
				F = (D & B) | ((^D) & C)
				g = (5*i + 1) % 16
			} else if i >= 32 && i <= 47 {
				// 3rd. round
				F = B ^ C ^ D
				g = (3*i + 5) % 16
			} else { // i >= 48 && i <= 63
				// 4th. round
				F = C ^ (B | (^D))
				g = (7 * i) % 16
			}

			F = F + A + KConstants[i] + M[g]
			A = D
			D = C
			C = B
			B = B + bits.RotateLeft32(F, int(KShiftAmounts[i]))
		}

		A += prevA
		B += prevB
		C += prevC
		D += prevD
	}

	// Convert the digest into a HexString
	digestBytes := bytes.NewBuffer([]byte{})
	if err := binary.Write(digestBytes, binary.LittleEndian, A); err != nil {
		return "", err
	}
	if err := binary.Write(digestBytes, binary.LittleEndian, B); err != nil {
		return "", err
	}
	if err := binary.Write(digestBytes, binary.LittleEndian, C); err != nil {
		return "", err
	}
	if err := binary.Write(digestBytes, binary.LittleEndian, D); err != nil {
		return "", err
	}
	return hex.EncodeToString(digestBytes.Bytes()), nil
}
