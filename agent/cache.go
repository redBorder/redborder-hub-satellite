package agent

import (
	"encoding/json"
	"os"
	"sync"

	"redborder-hub-satellite/common"
)

// DiskCache provides a thread-safe persistent store for caching metrics
// on disk when the WebSocket connection is down.
type DiskCache struct {
	mu   sync.Mutex
	path string
}

// NewDiskCache creates a new DiskCache instance.
func NewDiskCache(path string) *DiskCache {
	return &DiskCache{path: path}
}

// Add appends a new MetricSubmission to the cache file.
func (c *DiskCache) Add(sub common.MetricSubmission) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	subs, err := c.load()
	if err != nil {
		subs = []common.MetricSubmission{}
	}

	subs = append(subs, sub)
	return c.save(subs)
}

// PopAll returns all cached MetricSubmission entries.
func (c *DiskCache) PopAll() ([]common.MetricSubmission, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.load()
}

// RemoveOldest removes the first n elements from the cache.
func (c *DiskCache) RemoveOldest(n int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	subs, err := c.load()
	if err != nil {
		return err
	}

	if len(subs) <= n {
		return os.Remove(c.path)
	}

	return c.save(subs[n:])
}

func (c *DiskCache) load() ([]common.MetricSubmission, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var subs []common.MetricSubmission
	if err := json.Unmarshal(data, &subs); err != nil {
		return nil, err
	}
	return subs, nil
}

func (c *DiskCache) save(subs []common.MetricSubmission) error {
	data, err := json.Marshal(subs)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0600)
}
