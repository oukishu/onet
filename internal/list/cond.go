package list

// Size returns the number of elements. Alias of Len for compatibility
// with sing/common/x/list callers.
func (l List[T]) Size() int {
	return l.len
}

// IsEmpty reports whether the list contains no elements.
func (l List[T]) IsEmpty() bool {
	return l.len == 0
}

// PopBack removes and returns the last element's value.
// Returns the zero value of T if the list is empty.
func (l *List[T]) PopBack() T {
	if l.len == 0 {
		var zero T
		return zero
	}
	entry := l.root.prev
	l.remove(entry)
	return entry.Value
}

// PopFront removes and returns the first element's value.
// Returns the zero value of T if the list is empty.
func (l *List[T]) PopFront() T {
	if l.len == 0 {
		var zero T
		return zero
	}
	entry := l.root.next
	l.remove(entry)
	return entry.Value
}

// Array returns a snapshot of all element values as a slice.
// Returns nil if the list is empty.
// The returned slice is safe to iterate after the list is modified.
func (l *List[T]) Array() []T {
	if l.len == 0 {
		return nil
	}
	array := make([]T, 0, l.len)
	for e := l.Front(); e != nil; e = e.Next() {
		array = append(array, e.Value)
	}
	return array
}
