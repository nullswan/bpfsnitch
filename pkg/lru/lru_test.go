package lru

import (
	"sync"
	"testing"
)

func TestLRUCache(t *testing.T) {
	t.Parallel()

	cache := New[int, int](2) // Create LRUCache with capacity of 2

	cache.Put(1, 1)
	cache.Put(2, 2)

	if value, found := cache.Get(1); !found || value != 1 {
		t.Errorf(
			"Expected key 1 to have value 1, but got value %v found %v",
			value,
			found,
		)
	}

	cache.Put(3, 3)

	if _, found := cache.Get(2); found {
		t.Errorf("Expected key 2 to be evicted, but it was found")
	}

	cache.Put(4, 4)

	if _, found := cache.Get(1); found {
		t.Errorf("Expected key 1 to be evicted, but it was found")
	}

	if value, found := cache.Get(3); !found || value != 3 {
		t.Errorf(
			"Expected key 3 to have value 3, but got value %v found %v",
			value,
			found,
		)
	}

	if value, found := cache.Get(4); !found || value != 4 {
		t.Errorf(
			"Expected key 4 to have value 4, but got value %v found %v",
			value,
			found,
		)
	}
}

func TestLRUCacheOverwrite(t *testing.T) {
	t.Parallel()

	cache := New[int, int](2)
	cache.Put(1, 1)
	cache.Put(1, 10)
	if value, found := cache.Get(1); !found || value != 10 {
		t.Errorf(
			"Expected key 1 to have value 10, but got value %v found %v",
			value,
			found,
		)
	}
}

func TestLRUCacheEvictionOrder(t *testing.T) {
	t.Parallel()

	cache := New[int, int](3)
	cache.Put(1, 1)
	cache.Put(2, 2)
	cache.Put(3, 3)
	cache.Get(1) // Make key 1 the most recently used
	cache.Put(4, 4)
	if _, found := cache.Get(2); found {
		t.Errorf("Expected key 2 to be evicted, but it was found")
	}
}

func TestLRUCacheBoundaryUsage(t *testing.T) {
	t.Parallel()

	cache := New[int, int](1)
	cache.Put(1, 1)
	if value, found := cache.Get(1); !found || value != 1 {
		t.Errorf(
			"Expected key 1 to have value 1, but got value %v found %v",
			value,
			found,
		)
	}
	cache.Put(2, 2)
	if _, found := cache.Get(1); found {
		t.Errorf("Expected key 1 to be evicted, but it was found")
	}
	if value, found := cache.Get(2); !found || value != 2 {
		t.Errorf(
			"Expected key 2 to have value 2, but got value %v found %v",
			value,
			found,
		)
	}
}

func TestLRUCacheZeroCapacity(t *testing.T) {
	t.Parallel()

	cache := New[int, int](0)
	cache.Put(1, 1)
	if value, found := cache.Get(1); !found || value != 1 {
		t.Errorf(
			"Expected key 1 to be added with value 1, but got value %v found %v",
			value,
			found,
		)
	}
	cache.Put(2, 2)
	if value, found := cache.Get(2); !found || value != 2 {
		t.Errorf(
			"Expected key 2 to be added with value 2, but got value %v found %v",
			value,
			found,
		)
	}
	if _, found := cache.Get(1); found {
		t.Errorf(
			"Expected key 1 to be evicted after adding key 2, but it was found",
		)
	}
}

func TestLRUCacheConcurrency(t *testing.T) {
	t.Parallel()

	cache := New[int, int](100) // Create LRUCache with capacity of 100
	wg := sync.WaitGroup{}

	// Function to perform a sequence of puts and gets
	concurrentAccess := func(start, end int) {
		defer wg.Done()
		for i := start; i < end; i++ {
			cache.Put(i, i)
			if value, found := cache.Get(i); !found || value != i {
				t.Errorf(
					"Expected key %v to have value %v, but got value %v found %v",
					i,
					i,
					value,
					found,
				)
			}
		}
	}

	// Perform concurrent access to the cache
	threads := 10
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go concurrentAccess(i*10, (i+1)*10)
	}

	wg.Wait()

	// Validate the cache contents
	for i := 0; i < 50; i++ {
		if value, found := cache.Get(i); !found || value != i {
			t.Errorf(
				"Expected key %v to have value %v, but got value %v found %v",
				i,
				i,
				value,
				found,
			)
		}
	}
}

func TestLRUCacheEvictionPattern(t *testing.T) {
	t.Parallel()

	cache := New[int, int](3)
	cache.Put(1, 1)
	cache.Put(2, 2)
	cache.Put(3, 3)
	cache.Get(2)
	cache.Get(3)
	cache.Put(4, 4)
	if _, found := cache.Get(1); found {
		t.Errorf("Expected key 1 to be evicted, but it was found")
	}
	if value, found := cache.Get(2); !found || value != 2 {
		t.Errorf(
			"Expected key 2 to have value 2, but got value %v found %v",
			value,
			found,
		)
	}
	if value, found := cache.Get(3); !found || value != 3 {
		t.Errorf(
			"Expected key 3 to have value 3, but got value %v found %v",
			value,
			found,
		)
	}
	if value, found := cache.Get(4); !found || value != 4 {
		t.Errorf(
			"Expected key 4 to have value 4, but got value %v found %v",
			value,
			found,
		)
	}
}

func TestLRUCacheMultipleEvictions(t *testing.T) {
	t.Parallel()

	cache := New[int, int](2)
	cache.Put(1, 1)
	cache.Put(2, 2)
	cache.Put(3, 3) // Causes eviction of key 1
	cache.Put(4, 4) // Causes eviction of key 2
	if _, found := cache.Get(1); found {
		t.Errorf("Expected key 1 to be evicted, but it was found")
	}
	if _, found := cache.Get(2); found {
		t.Errorf("Expected key 2 to be evicted, but it was found")
	}
	if value, found := cache.Get(3); !found || value != 3 {
		t.Errorf(
			"Expected key 3 to have value 3, but got value %v found %v",
			value,
			found,
		)
	}
	if value, found := cache.Get(4); !found || value != 4 {
		t.Errorf(
			"Expected key 4 to have value 4, but got value %v found %v",
			value,
			found,
		)
	}
}
