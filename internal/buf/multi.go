package buf

// LenMulti returns the total number of readable bytes across all buffers.
func LenMulti(buffers []*Buffer) int {
	var n int
	for _, b := range buffers {
		n += b.Len()
	}
	return n
}

// ToSliceMulti returns a [][]byte where each element is the readable slice of
// the corresponding Buffer. Replaces the original common.Map call with a
// plain loop to eliminate the sing/common dependency.
func ToSliceMulti(buffers []*Buffer) [][]byte {
	result := make([][]byte, len(buffers))
	for i, b := range buffers {
		result[i] = b.Bytes()
	}
	return result
}

// CopyMulti copies all readable bytes from buffers into dst sequentially.
// Returns the total number of bytes copied.
func CopyMulti(dst []byte, buffers []*Buffer) int {
	var n int
	for _, b := range buffers {
		n += copy(dst[n:], b.Bytes())
	}
	return n
}

// ReleaseMulti calls Release() on every buffer in the slice.
func ReleaseMulti(buffers []*Buffer) {
	for _, b := range buffers {
		b.Release()
	}
}
