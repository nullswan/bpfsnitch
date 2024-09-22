package lru

import (
	"container/list"
	"sync"
)

// Cache is a thread-safe fixed size LRU cache.
type Cache[K comparable, V any] struct {
	capacity int
	lock     sync.Mutex
	cache    map[K]*list.Element
	list     *list.List
}

type pair[K comparable, V any] struct {
	key   K
	value V
}

// New creates a new LRUCache with the given capacity.
func New[K comparable, V any](capacity int) *Cache[K, V] {
	return &Cache[K, V]{
		capacity: capacity,
		cache:    make(map[K]*list.Element),
		list:     list.New(),
	}
}

// Get retrieves the value of the key from the cache and marks the key as recently used.
func (c *Cache[K, V]) Get(key K) (value V, ok bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if elem, found := c.cache[key]; found {
		c.list.MoveToFront(elem)
		return elem.Value.(*pair[K, V]).value, true
	}
	var zeroValue V
	return zeroValue, false
}

// Put adds a key-value pair to the cache and evicts items if the cache is full.
func (c *Cache[K, V]) Put(key K, value V) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if elem, found := c.cache[key]; found {
		c.list.MoveToFront(elem)
		elem.Value.(*pair[K, V]).value = value
		return
	}

	if c.list.Len() >= c.capacity {
		backElem := c.list.Back()
		if backElem != nil {
			c.list.Remove(backElem)
			delete(c.cache, backElem.Value.(*pair[K, V]).key)
		}
	}

	entry := &pair[K, V]{key: key, value: value}
	elem := c.list.PushFront(entry)
	c.cache[key] = elem
}

// Remove removes the key from the cache.
func (c *Cache[K, V]) Remove(key K) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if elem, found := c.cache[key]; found {
		c.list.Remove(elem)
		delete(c.cache, key)
	}
}

// ForEach iterates over all elements in the cache and calls the given function for each element.
func (c *Cache[K, V]) ForEach(fn func(key K, value V) bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	for elem := c.list.Front(); elem != nil; elem = elem.Next() {
		p := elem.Value.(*pair[K, V])
		if !fn(p.key, p.value) {
			break
		}
	}
}
