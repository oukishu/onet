package buf

// Get borrows a []byte of the given size from the global allocator pool.
func Get(size int) []byte {
	if size == 0 {
		return nil
	}
	return DefaultAllocator.Get(size)
}

// Put returns a []byte to the global allocator pool.
func Put(buf []byte) error {
	return DefaultAllocator.Put(buf)
}
