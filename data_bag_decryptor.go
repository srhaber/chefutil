// Package decryptor provides a utility for decrypted data bags items.
package decryptor

import (
	"sync"

	"github.com/go-chef/chef"
)

// DataBagDecryptor is a struct that wraps a DataBagItem interface and a
// secret encryption key
type DataBagDecryptor struct {
	Item   map[string]interface{}
	Secret []byte
}

// DecryptItem decrypts the DataBagItem using the provided secret initialized
// in the DataBagDecryptor struct
func (d *DataBagDecryptor) DecryptItem() (chef.DataBagItem, error) {
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

		encryptedVal := NewEncryptedDataBagValue(encryptedValue)
		wg.Add(1)

		// This is the fun part! Decrypt each value concurrently.
		go func(e *EncryptedDataBagValue, key string) {
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
