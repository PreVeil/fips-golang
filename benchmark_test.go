package fips

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func benchmarkAesEncrypt(b *testing.B) {
	data, err := randBytes(2 * 1024 * 1024)
	require.NoError(b, err)
	for n := 0; n < b.N; n++ {
		// random iv
		key, err := randBytes(aesKeyLength)
		require.NoError(b, err)
		_, _, _, err = AesEncrypt(key, data, make([]byte, 0))
		require.NoError(b, err)
	}
}

func BenchmarkAesEncrypt(b *testing.B) {
	benchmarkAesEncrypt(b)
}

func TestBenchmarkAesEncrypt(t *testing.T) {
	result := testing.Benchmark(benchmarkAesEncrypt)
	fmt.Println(result.MemString(), result.String())
}
