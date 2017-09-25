package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-chef/chef"
	dec "github.com/srhaber/data-bag-decryptor"
)

// To run this example, start a chef-zero server:
//
//    chef-zero --log-level debug
//
// Add an encrypted data bag and populate it with some key-vals.
//
//    knife data bag create my-bag my-item --server-url=http://127.0.0.1:8889 --secret=abcdef1234
//
func main() {
	// Read a client key
	key, err := ioutil.ReadFile("example_key.pem")
	if err != nil {
		fmt.Println("Couldn't read example_key.pem:", err)
		os.Exit(1)
	}

	// Build a client
	client, err := chef.NewClient(&chef.Config{
		Name:    "MyName",
		Key:     string(key),
		BaseURL: "http://127.0.0.1:8889",
	})

	if err != nil {
		fmt.Println("Issue setting up client:", err)
		os.Exit(1)
	}

	encryptedDataBagSecret := []byte("abcdef1234")

	// Get the encrypted data bag item using chef client.
	item, err := client.DataBags.GetItem("my-bag", "my-item")
	if err != nil {
		fmt.Println("Error getting item:", err)
	}

	// Build a DataBagDecryptor
	decryptor := &dec.DataBagDecryptor{
		Item:   item.(map[string]interface{}),
		Secret: encryptedDataBagSecret,
	}

	// Decrypt the item
	decryptedItem, err := decryptor.DecryptItem()
	if err != nil {
		fmt.Println("Error decrypting item:", err)
	}

	// Print the decryped item
	fmt.Println("Got item:", decryptedItem)
}
