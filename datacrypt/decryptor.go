// Package datacrypt provides a utility for decrypted data bags items.
package datacrypt

import (
	"sync"

	"github.com/go-chef/chef"
)

// Decryptor is an interface that provides functionality for decrypting a Chef data bag
type Decryptor interface {
	// Decrypt returns a chef.DataBagItem, or an error
	// `chef.DataBagItem` is an `interface{}`. Although we can return a more specific type
	// here, mainly `map[string]string`, it feels appropriate to use interface{} so we
	// match what the go-chef client returns for an unencrypted data bag.
	Decrypt() (chef.DataBagItem, error)
}

// DataDecryptor is a struct that implements Decryptor
type DataDecryptor struct {
	// Item is typically a chef.DataBagItem returned from the Chef server
	Item map[string]interface{}

	// Secret is the encryption secret key
	Secret []byte
}

// Decrypt attempts to decrypts the Item using the given Secret in the underlying
// DataDecryptor struct.
func (d *DataDecryptor) Decrypt() (chef.DataBagItem, error) {
	item := map[string]string{
		"id": d.Item["id"].(string),
	}

	// WaitGroup allows all goroutines to finish before this function returns
	var wg sync.WaitGroup

	// Mutex provides safe access for writing to item `map[string]string`
	var mux sync.Mutex

	for key, encryptedValue := range d.Item {
		if key == "id" {
			continue
		}

		encryptedVal := NewEncryptedValue(encryptedValue)
		wg.Add(1)

		// This is the fun part! Decrypt each value concurrently.
		go func(e *EncryptedValue, key string) {
			ch := make(chan string)

			go func(ch <-chan string) {
				defer wg.Done()
				val := <-ch

				// Writing to map must be guarded against concurrency
				mux.Lock()
				item[key] = val
				mux.Unlock()
			}(ch)

			// We're swallowing any returned error here. There's probably a good way
			// to bubble this up, but I'm not sure what the best approach is.
			val, _ := e.DecryptValue(d.Secret)
			ch <- val
		}(encryptedVal, key)
	}

	wg.Wait()
	return item, nil
}
