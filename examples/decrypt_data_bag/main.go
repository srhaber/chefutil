// To run this example, start a chef-zero server:
//
//    chef-zero --log-level debug
//
// Add an encrypted data bag and populate it with some key-vals.
//
//    knife data bag create my-bag my-item --server-url=http://127.0.0.1:8889 --secret=abcdef1234
//

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-chef/chef"
	"github.com/srhaber/chefutil/datacrypt"
)

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

	// Build a DataDecryptor
	decryptor := &datacrypt.DataDecryptor{
		Item:   item.(map[string]interface{}),
		Secret: encryptedDataBagSecret,
	}

	// Decrypt the item
	decryptedItem, err := decryptor.Decrypt()
	if err != nil {
		fmt.Println("Error decrypting item:", err)
	}

	// Print the decryped item
	fmt.Println("Got item:", decryptedItem)
	// Output: Got item: map[id:my-item hello:world]
}
