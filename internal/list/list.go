// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

// Package list implements a generic doubly linked list.
//
// To iterate over a list (where l is a *List[T]):
//
//	for e := l.Front(); e != nil; e = e.Next() {
//	    // do something with e.Value
//	}
package list

// Element is a node in a doubly linked list.
type Element[T any] struct {
	// Next and previous pointers in the doubly-linked list of elements.
	// Internally the list is a ring: &l.root is both the successor of the
	// last element and the predecessor of the first element.
	next, prev *Element[T]

	// The list to which this element belongs.
	list *List[T]

	// Value is the value stored in this element.
	Value T
}

// Next returns the next list element, or nil if this is the last element.
func (e *Element[T]) Next() *Element[T] {
	if p := e.next; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

// Prev returns the previous list element, or nil if this is the first element.
func (e *Element[T]) Prev() *Element[T] {
	if p := e.prev; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

// List is a generic doubly linked list.
// The zero value is an empty list ready to use.
type List[T any] struct {
	root Element[T] // sentinel element; only root.prev and root.next are used
	len  int        // current list length, excluding sentinel
}

// Init clears the list and returns it.
func (l *List[T]) Init() *List[T] {
	l.root.next = &l.root
	l.root.prev = &l.root
	l.len = 0
	return l
}

// Len returns the number of elements. O(1).
func (l *List[T]) Len() int { return l.len }

// Front returns the first element, or nil if the list is empty.
func (l *List[T]) Front() *Element[T] {
	if l.len == 0 {
		return nil
	}
	return l.root.next
}

// Back returns the last element, or nil if the list is empty.
func (l *List[T]) Back() *Element[T] {
	if l.len == 0 {
		return nil
	}
	return l.root.prev
}

// lazyInit initializes a zero List on first use.
func (l *List[T]) lazyInit() {
	if l.root.next == nil {
		l.Init()
	}
}

func (l *List[T]) insert(e, at *Element[T]) *Element[T] {
	e.prev = at
	e.next = at.next
	e.prev.next = e
	e.next.prev = e
	e.list = l
	l.len++
	return e
}

func (l *List[T]) insertValue(v T, at *Element[T]) *Element[T] {
	e := &Element[T]{Value: v}
	return l.insert(e, at)
}

func (l *List[T]) remove(e *Element[T]) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil // prevent memory leaks
	e.prev = nil
	e.list = nil
	l.len--
}

// Remove removes e from l if e belongs to l, and returns e.Value.
// e must not be nil.
func (l *List[T]) Remove(e *Element[T]) T {
	if e.list == l {
		l.remove(e)
	}
	return e.Value
}

// PushFront inserts a new element with value v at the front of the list.
func (l *List[T]) PushFront(v T) *Element[T] {
	l.lazyInit()
	return l.insertValue(v, &l.root)
}

// PushBack inserts a new element with value v at the back of the list.
func (l *List[T]) PushBack(v T) *Element[T] {
	l.lazyInit()
	return l.insertValue(v, l.root.prev)
}

// InsertBefore inserts a new element with value v immediately before mark.
// mark must belong to l.
func (l *List[T]) InsertBefore(v T, mark *Element[T]) *Element[T] {
	if mark.list != l {
		return nil
	}
	return l.insertValue(v, mark.prev)
}

// InsertAfter inserts a new element with value v immediately after mark.
// mark must belong to l.
func (l *List[T]) InsertAfter(v T, mark *Element[T]) *Element[T] {
	if mark.list != l {
		return nil
	}
	return l.insertValue(v, mark)
}

func (l *List[T]) move(e, at *Element[T]) {
	if e == at {
		return
	}
	e.prev.next = e.next
	e.next.prev = e.prev
	e.prev = at
	e.next = at.next
	e.prev.next = e
	e.next.prev = e
}

// MoveToFront moves e to the front of l. e must belong to l.
func (l *List[T]) MoveToFront(e *Element[T]) {
	if e.list != l || l.root.next == e {
		return
	}
	l.move(e, &l.root)
}

// MoveToBack moves e to the back of l. e must belong to l.
func (l *List[T]) MoveToBack(e *Element[T]) {
	if e.list != l || l.root.prev == e {
		return
	}
	l.move(e, l.root.prev)
}

// MoveBefore moves e to its new position before mark.
// Both e and mark must belong to l and must not be equal.
func (l *List[T]) MoveBefore(e, mark *Element[T]) {
	if e.list != l || e == mark || mark.list != l {
		return
	}
	l.move(e, mark.prev)
}

// MoveAfter moves e to its new position after mark.
// Both e and mark must belong to l and must not be equal.
func (l *List[T]) MoveAfter(e, mark *Element[T]) {
	if e.list != l || e == mark || mark.list != l {
		return
	}
	l.move(e, mark)
}

// PushBackList appends a copy of other at the back of l.
// l and other may be the same list.
func (l *List[T]) PushBackList(other *List[T]) {
	l.lazyInit()
	for i, e := other.Len(), other.Front(); i > 0; i, e = i-1, e.Next() {
		l.insertValue(e.Value, l.root.prev)
	}
}

// PushFrontList prepends a copy of other at the front of l.
// l and other may be the same list.
func (l *List[T]) PushFrontList(other *List[T]) {
	l.lazyInit()
	for i, e := other.Len(), other.Back(); i > 0; i, e = i-1, e.Prev() {
		l.insertValue(e.Value, &l.root)
	}
}

// List returns the list e belongs to, or nil.
func (e *Element[T]) List() *List[T] {
	return e.list
}
