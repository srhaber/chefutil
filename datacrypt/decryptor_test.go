package datacrypt

import (
	"testing"
)

func TestDecrypt(t *testing.T) {
	d := &DataDecryptor{
		Item:   testEncryptedDataBagFixture(),
		Secret: testEncryptedDataBagSecret(),
	}

	dataBagItem, err := d.Decrypt()
	if err != nil {
		t.Error("Got error: ", err)
	}

	obj := dataBagItem.(map[string]string)

	if obj["hello"] != "world" {
		t.Errorf("Expected `hello: world`, got `hello %v`", obj["hello"])
	}

	if obj["goodnight"] != "moon" {
		t.Errorf("Expected `goodnight: moon`, got `goodnight %v`", obj["goodnight"])
	}

	if obj["yellow"] != "submarine" {
		t.Errorf("Expected `yellow: submarine`, got `yellow %v`", obj["yellow"])
	}
}

func testEncryptedDataBagFixture() map[string]interface{} {
	return map[string]interface{}{
		"id": "test_data_bag_encrypted",
		"hello": map[string]interface{}{
			"encrypted_data": "Q00eu4hnTT3/JrYdOPM0fkQ0puQt49EfJUnVC6ywmBQ=\n",
			"hmac":           "g8r27e5bgIEIZG80sWYz562cqmkAzzQqz5ZIcn6IVC0=\n",
			"iv":             "8/fyARkSZHiG8tYEZuw4Bg==\n",
			"version":        2,
			"cipher":         "aes-256-cbc",
		},
		"goodnight": map[string]interface{}{
			"encrypted_data": "5ECoTaom+wX9BJVAbG/G+kgImPA//hcQtal7pFWXfTA=\n",
			"hmac":           "DGFvUeeFg4eb6jy81qv4iLslB9Pb/4NqOlzuOjiyB9E=\n",
			"iv":             "rrNIUcFjwhnktFRlhcxs+g==\n",
			"version":        2,
			"cipher":         "aes-256-cbc",
		},
		"yellow": map[string]interface{}{
			"encrypted_data": "4VRxejugysgNY69BMLpwZhV1D66G6xQ8IMBMPzzsE9c=\n",
			"hmac":           "b5Z97FPB9wN0kb/nQHXdgx2ckAU9g6OieilWV9SKOJY=\n",
			"iv":             "VcK/tAR3dsNzRCo6WkwRqQ==\n",
			"version":        2,
			"cipher":         "aes-256-cbc",
		},
	}
}
