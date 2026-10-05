package l0

// lru.go — a bounded, concurrency-safe LRU cache (stdlib only, via
// container/list). Replaces the blunt "clear the whole map when it hits
// 4096" idempotency cache (api.go): true least-recently-used eviction
// keeps the live working set and drops only cold keys, so memory is
// O(capacity) and a burst of unique keys never wipes a hot entry.

import (
	"container/list"
	"sync"
)

type lruEntry[K comparable, V any] struct {
	key K
	val V
}

// LRU is a fixed-capacity least-recently-used cache. Get promotes an entry
// to most-recently-used; Put evicts the least-recently-used entry when the
// cache is full. Safe for concurrent use.
type LRU[K comparable, V any] struct {
	mu  sync.Mutex
	cap int
	ll  *list.List
	idx map[K]*list.Element
}

// NewLRU returns an LRU holding at most capacity entries (min 1).
func NewLRU[K comparable, V any](capacity int) *LRU[K, V] {
	if capacity < 1 {
		capacity = 1
	}
	return &LRU[K, V]{cap: capacity, ll: list.New(), idx: map[K]*list.Element{}}
}

// Get returns the value for key and marks it most-recently-used.
func (c *LRU[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero V
	el, ok := c.idx[key]
	if !ok {
		return zero, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(lruEntry[K, V]).val, true
}

// Put inserts or updates key, evicting the LRU entry when over capacity.
func (c *LRU[K, V]) Put(key K, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[key]; ok {
		el.Value = lruEntry[K, V]{key: key, val: val}
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(lruEntry[K, V]{key: key, val: val})
	c.idx[key] = el
	if c.ll.Len() > c.cap {
		if oldest := c.ll.Back(); oldest != nil {
			c.ll.Remove(oldest)
			delete(c.idx, oldest.Value.(lruEntry[K, V]).key)
		}
	}
}

// Delete removes key if present.
func (c *LRU[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[key]; ok {
		c.ll.Remove(el)
		delete(c.idx, key)
	}
}

// Len returns the number of cached entries.
func (c *LRU[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}