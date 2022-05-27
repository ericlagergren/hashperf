package hashperf

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"hash/maphash"
	"strconv"
	"testing"

	"github.com/cespare/xxhash"
	"github.com/dchest/siphash"
	"github.com/ericlagergren/polyval"
	"github.com/minio/highwayhash"
	"github.com/zeebo/xxh3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

func BenchmarkBaseline(b *testing.B) {
	bench(b, baseline{})
}

type baseline struct{}

var _ hash.Hash = baseline{}

func (baseline) Write(p []byte) (int, error) { return 0, nil }
func (baseline) Sum(_ []byte) []byte         { return nil }
func (baseline) Reset()                      {}
func (baseline) Size() int                   { return 0 }
func (baseline) BlockSize() int              { return 0 }

func BenchmarkBLAKE2b256(b *testing.B) {
	h, _ := blake2b.New256(nil)
	bench(b, h)
}

func BenchmarkBLAKE2b512(b *testing.B) {
	h, _ := blake2b.New512(nil)
	bench(b, h)
}

func BenchmarkBLAKE2s256(b *testing.B) {
	h, _ := blake2s.New256(nil)
	bench(b, h)
}

func BenchmarkCRC32(b *testing.B) {
	bench(b, crc32.NewIEEE())
}

func BenchmarkFNV64a(b *testing.B) {
	bench(b, fnv.New64a())
}

func BenchmarkFNV128a(b *testing.B) {
	bench(b, fnv.New128a())
}

func BenchmarkHighwayHash64(b *testing.B) {
	key := make([]byte, 32)
	h, _ := highwayhash.New(key)
	bench(b, h)
}

func BenchmarkHighwayHash128(b *testing.B) {
	key := make([]byte, 32)
	h, _ := highwayhash.New(key)
	bench(b, h)
}

func BenchmarkHighwayHash256(b *testing.B) {
	key := make([]byte, 32)
	h, _ := highwayhash.New(key)
	bench(b, h)
}

func BenchmarkMaphash(b *testing.B) {
	var h maphash.Hash
	bench(b, &h)
}

func BenchmarkMD5(b *testing.B) {
	bench(b, md5.New())
}

func BenchmarkPOLYVAL(b *testing.B) {
	key := make([]byte, 16)
	key[0] = 1
	var p poly
	p.Init(key)
	bench(b, &p)
}

type poly struct {
	polyval.Polyval
}

func (p *poly) Write(data []byte) (int, error) {
	p.Update(data)
	return len(data), nil
}

func BenchmarkSipHash64(b *testing.B) {
	key := make([]byte, 16)
	bench(b, siphash.New(key))
}

func BenchmarkSipHash128(b *testing.B) {
	key := make([]byte, 16)
	bench(b, siphash.New128(key))
}

func BenchmarkSHA1(b *testing.B) {
	bench(b, sha1.New())
}

func BenchmarkSHA256(b *testing.B) {
	bench(b, sha256.New())
}

func BenchmarkSHA512(b *testing.B) {
	bench(b, sha512.New())
}

func BenchmarkXxHash(b *testing.B) {
	bench(b, xxhash.New())
}

func BenchmarkXXH3Hash(b *testing.B) {
	bench(b, xxh3.New())
}

func bench(b *testing.B, h hash.Hash) {
	for size := 1; size <= 8192; size *= 2 {
		if _, ok := h.(*poly); ok && size < 16 {
			// POLYVAL only supports 16-byte blocks.
			continue
		}
		data := make([]byte, size)
		name := strconv.Itoa(size)
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				h.Write(data)
			}
		})
	}
}
