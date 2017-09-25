package chef

import (
	"sync"

	"github.com/go-chef/chef"
)

type DataBagDecryptor struct {
	Item   map[string]interface{}
	Secret []byte
}

func (d *DataBagDecryptor) DecryptItem() (chef.DataBagItem, error) {
	item := map[string]string{
		"id": d.Item["id"].(string),
	}

	var wg sync.WaitGroup
	var mux sync.Mutex

	for key, encryptedValue := range d.Item {
		if key == "id" {
			continue
		}

		encryptedVal := NewEncryptedDataBagValue(encryptedValue)
		wg.Add(1)

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

			val, _ := e.DecryptValue(d.Secret)
			ch <- val
		}(encryptedVal, key)
	}

	wg.Wait()
	return item, nil
}
