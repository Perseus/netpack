package netpack


import (

	"time"
	"sync"
	"sort"
	"fmt"
)



// CacheItem is a struct containing the data that will be stored in the cache and
// the expiration time for the item.

type CacheItem struct {
	data NetFace
	expiration time.Time
}


// CheckExpiry checks whether the particular cache item has expired or not
func CheckExpiry(expiryTime time.Time) bool {

	expired := expiryTime.Before(time.Now())
	return expired

}

// Cache is the overall struct which stores the cached items
type Cache struct {

	// items is a map of cache items that will be present in the cache at any given time
	items map[string]*CacheItem

	// Mutexes are used to make sure that at a given time only a read or a write operation is being done on the cache
	// Any function that reads or writes to the catch will lock the thread so that it is the only one using it.
	// The thread will be unlocked after the function is done with it's process
	lock sync.RWMutex
}


// expiryChecker takes an interval as a parameter, ticks for that duration and then performs 
// a cleaning of expired cache items
func expiryChecker(c *Cache, interval time.Duration) {
	ticker := time.Tick(interval)

	for {
		select {
		case <- ticker:
				c.DeleteExpired()
		}
	}
}

// CreateNewCache creates a new cache with an object of NetPack provided in the parameter. 
// It creates a new object of the Cache struct.

func CreateNewCache() (*Cache)  {
	items := make(map[string]*CacheItem)

	cache := &Cache {
			items:	items,
	}
	go expiryChecker(cache, 1*time.Second) 

	return cache
}




// GetItem checks the cache whether an item exists already or not. If not, it returns nil
// if the item exists, it returns the item.

func (c *Cache) GetItem(itemName string) interface{} {

		c.lock.RLock()
		defer c.lock.RUnlock()
		item, check := c.items[itemName]
		if !(check) || (CheckExpiry(item.expiration) == true) {
			return nil
		}

		return item.data
}


// AddItem adds an item to the cache with an expiration time

func (c *Cache) AddItem(hash string, item NetFace, expiration time.Duration) bool {
		// check if that item exists or not
		itemExists := c.GetItem(hash)
		if itemExists != nil {
			return false
		}

		c.lock.RLock()
		defer c.lock.RUnlock()

		c.items[hash] = &CacheItem {
			data: item,
			expiration: time.Now().Add(expiration),
		}
		
		return true
}

// DeleteExpired deletes all the expired items in the cache

func (c *Cache) DeleteExpired() {
	c.lock.Lock()
	defer c.lock.Unlock()

		for i,j := range c.items {
			if CheckExpiry(j.expiration) == true {
				delete(c.items, i)
			}
		}
}

// GetCount returns the number of total elements in the cache
func (c *Cache) GetCount() int {
	return len(c.items)
}


// GetAllItems returns all the items of the cache in string format
func (c *Cache) GetAllItems() string {
	var str string
	var keys []string

	c.lock.RLock()
	defer c.lock.RUnlock()

	for k := range c.items {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	str += "\n"

	
	for _, k := range keys {
			str += k + " " + fmt.Sprintf("%v", c.items[k].data) + "\n"
	}

	return str
}