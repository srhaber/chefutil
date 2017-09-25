package decryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// EncryptedDataBagValue contains the values found for each item in an encrypted
// datq bag. This implementation assumes the data bags were encrypted using version 2.
type EncryptedDataBagValue struct {
	encryptedData []byte
	hmac          []byte
	iv            []byte
	version       int
	cipher        string
}

// NewEncryptedDataBagValue is a constructor that takes a chef.DataBagItem interface,
// initializes an EncryptedDataBagValue, and returns its pointer.
func NewEncryptedDataBagValue(encryptedValues interface{}) *EncryptedDataBagValue {
	if values, ok := encryptedValues.(map[string]interface{}); ok {
		obj := new(EncryptedDataBagValue)

		// Use type assertions to delineate between string and []byte types.
		if v, ok := values["encrypted_data"]; ok {
			switch t := v.(type) {
			case []byte:
				obj.encryptedData = t
			case string:
				obj.encryptedData = []byte(t)
			}
		}

		if v, ok := values["hmac"]; ok {
			switch t := v.(type) {
			case []byte:
				obj.hmac = t
			case string:
				obj.hmac = []byte(t)
			}
		}

		if v, ok := values["iv"]; ok {
			switch t := v.(type) {
			case []byte:
				obj.iv = t
			case string:
				obj.iv = []byte(t)
			}
		}

		// Go may interpret `version` as a float64, so use a type assertion to
		// check for that and int.
		if v, ok := values["version"]; ok {
			switch t := v.(type) {
			case int:
				obj.version = t
			case float64:
				obj.version = int(t)
			}
		}

		if v, ok := values["cipher"]; ok {
			obj.cipher = v.(string)
		}

		return obj
	}
	return nil
}

// DecryptValue takes an encryption secret and returns the decrypted value of the
// underlying EncryptedDataBagValue or an error if any occurs.
func (obj *EncryptedDataBagValue) DecryptValue(secret []byte) (string, error) {
	err := obj.validateHmac(secret)
	if err != nil {
		return "", err
	}

	if obj.cipher != "aes-256-cbc" {
		return "", fmt.Errorf("Encryption algorithm is incorrect.")
	}

	encryptedDataBytes, err := base64.StdEncoding.DecodeString(string(obj.encryptedData))
	if err != nil {
		return "", err
	}

	ivBytes, err := base64.StdEncoding.DecodeString(string(obj.iv))
	if err != nil {
		return "", err
	}

	shaKey := sha256.Sum256(secret)
	block, err := aes.NewCipher(shaKey[:])
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, ivBytes)
	mode.CryptBlocks(encryptedDataBytes, encryptedDataBytes)

	return obj.parseJSON(encryptedDataBytes)
}

// validateHmac performs an extra HMAC check, required by version 2 encryption algorithm
// It returns an error if the HMAC is invalid.
func (obj *EncryptedDataBagValue) validateHmac(secret []byte) error {
	candidateHmacBytes, err := base64.StdEncoding.DecodeString(string(obj.hmac))
	if err != nil {
		return err
	}

	hmacHash := hmac.New(sha256.New, secret)
	hmacHash.Write(obj.encryptedData)
	expectedHmacBytes := hmacHash.Sum(nil)

	if !hmac.Equal(candidateHmacBytes, expectedHmacBytes) {
		return fmt.Errorf("Error decrypting data bag value: invalid hmac. Most likely the provided key is incorrect.")
	}

	return nil
}

// parseJSON takes the decrypted raw data, which is a marshaled JSON string, and retrieves
// and returns the actual value we care about.
func (obj *EncryptedDataBagValue) parseJSON(byteSlice []byte) (string, error) {
	reader := bytes.NewReader(byteSlice)
	seenKey := false

	// The marshaled JSON string is `{"json_wrapper":"the_value"}`
	dec := json.NewDecoder(reader)

	// Sometimes the byteSlice contains junk data after the last JSON delim `}`
	// This junk data causes the Unmarshal function to fail. As a workaround,
	// we parse the JSON one token at a time until we get the desired token.
	// We can do this since we have a well-defined marshaled string of the JSON object
	for {
		t, err := dec.Token()
		if err != nil {
			return "", err
		}

		// If we have a string and...
		if val, ok := t.(string); ok {
			// If we've already seen the json_wrapper key, then assume we have the value
			if seenKey {
				return val, nil
			}
			seenKey = true
		}
	}

	return "", fmt.Errorf("Unable to parse result JSON")
}
