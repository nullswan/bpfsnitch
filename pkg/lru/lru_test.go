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

func TestLRUCacheRemove(t *testing.T) {
	t.Parallel()

	cache := New[int, int](2)

	cache.Put(1, 100)
	cache.Put(2, 200)

	cache.Remove(1)

	if _, found := cache.Get(1); found {
		t.Errorf("Expected key 1 to be removed, but it was found")
	}

	if value, found := cache.Get(2); !found || value != 200 {
		t.Errorf(
			"Expected key 2 to have value 200, but got value %v found %v",
			value,
			found,
		)
	}

	cache.Put(3, 300)

	if value, found := cache.Get(3); !found || value != 300 {
		t.Errorf(
			"Expected key 3 to have value 300, but got value %v found %v",
			value,
			found,
		)
	}
}

func TestLRUCacheForEach(t *testing.T) {
	t.Parallel()

	cache := New[int, int](3)
	cache.Put(1, 100)
	cache.Put(2, 200)
	cache.Put(3, 300)

	// Expected order: 3 (MRU), 2, 1 (LRU)
	expectedKeys := []int{3, 2, 1}
	index := 0

	cache.ForEach(func(key int, _ int) bool {
		if index >= len(expectedKeys) {
			t.Errorf("Iterated over more elements than expected")
			return false
		}
		expectedKey := expectedKeys[index]
		if key != expectedKey {
			t.Errorf(
				"Expected key %v at index %v, but got key %v",
				expectedKey,
				index,
				key,
			)
		}
		index++
		return true
	})

	if index != len(expectedKeys) {
		t.Errorf(
			"Expected to iterate over %v elements, but iterated over %v",
			len(expectedKeys),
			index,
		)
	}
}

func TestLRUCacheForEachEarlyExit(t *testing.T) {
	t.Parallel()

	cache := New[int, int](1)
	cache.Put(1, 100)
	cache.Put(2, 200)
	cache.Put(3, 300)

	// Expected to stop after first element
	index := 0

	cache.ForEach(func(_ int, _ int) bool {
		index++
		return false
	})

	if index != 1 {
		t.Errorf(
			"Expected to iterate over 1 element, but iterated over %v",
			index,
		)
	}
}

func TestLRUCacheForEachEmptyCache(t *testing.T) {
	t.Parallel()

	cache := New[int, int](1)

	called := false

	cache.ForEach(func(_ int, _ int) bool {
		called = true
		return true
	})

	if called {
		t.Errorf("Expected ForEach not to call the function on an empty cache")
	}
}

func TestLRUCacheForEachAfterOperations(t *testing.T) {
	t.Parallel()

	cache := New[int, int](3)
	cache.Put(1, 100) // [1]
	cache.Put(2, 200) // [2, 1]
	cache.Get(1)      // Make key 1 MRU [1, 2]
	cache.Put(3, 300) // [3, 1, 2]
	cache.Get(2)      // Now key 2 is MRU [2, 3, 1]
	cache.Put(4, 400) // Evicts key 3 (LRU) [4, 2, 3]

	// Expected order: 2 (MRU), 1, 4
	expectedKeys := []int{4, 2, 3}
	index := 0

	cache.ForEach(func(key int, _ int) bool {
		if index >= len(expectedKeys) {
			t.Errorf("Iterated over more elements than expected")
			return false
		}
		expectedKey := expectedKeys[index]
		if key != expectedKey {
			t.Errorf(
				"Expected key %v at index %v, but got key %v",
				expectedKey,
				index,
				key,
			)
		}
		index++
		return true
	})

	if index != len(expectedKeys) {
		t.Errorf(
			"Expected to iterate over %v elements, but iterated over %v",
			len(expectedKeys),
			index,
		)
	}
}
