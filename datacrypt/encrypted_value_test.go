package datacrypt

import (
	"bytes"
	"testing"
)

func TestNewEncryptedValue(t *testing.T) {
	encryptedValues := testEncryptedValueFixture()
	obj := NewEncryptedValue(encryptedValues)

	if !bytes.Equal(encryptedValues["encrypted_data"].([]byte), obj.encryptedData) {
		t.Error("encryptedData field not correctly set in struct")
	}

	if !bytes.Equal(encryptedValues["hmac"].([]byte), obj.hmac) {
		t.Error("hmac field not correctly set in struct")
	}

	if !bytes.Equal(encryptedValues["iv"].([]byte), obj.iv) {
		t.Error("iv field not correctly set in struct")
	}

	if encryptedValues["version"].(int) != obj.version {
		t.Error("version field not correctly set in struct")
	}

	if encryptedValues["cipher"].(string) != obj.cipher {
		t.Error("cipher field not correctly set in struct")
	}
}

func TestNewEncryptedValue_nil(t *testing.T) {
	obj := NewEncryptedValue("blah")
	if obj != nil {
		t.Error("Invalid argument to constructor should return nil")
	}
}

func TestValidateHmac(t *testing.T) {
	obj := NewEncryptedValue(testEncryptedValueFixture())

	// Should be good
	err := obj.validateHmac(testEncryptedDataBagSecret())
	if err != nil {
		t.Error(err)
	}

	// Should be invalid
	err = obj.validateHmac([]byte("wrong_secret"))
	if err == nil {
		t.Error("validateHmac should not succeed with incorrect secret")
	}
}

func TestDecryptValue(t *testing.T) {
	obj := NewEncryptedValue(testEncryptedValueFixture())

	val, err := obj.DecryptValue(testEncryptedDataBagSecret())
	if err != nil {
		t.Error(err)
	}

	if val != testEncryptedDataBagVal() {
		t.Errorf("Got value: %v, expected value: %v\n", val, testEncryptedDataBagVal())
	}
}

// Helper functions

func testEncryptedValueFixture() map[string]interface{} {
	return map[string]interface{}{
		"encrypted_data": []byte("AKyDsX/eiYImvjJljM8By3zi6fR7ekqhqEY1sPSOYK0=\n"),
		"hmac":           []byte("CDtQRHLtY1ohbnH27BEm6hxskEsj/lLa45SHHZHoABQ=\n"),
		"iv":             []byte("4tDhUVRqApUlKC11q5gA5A==\n"),
		"version":        2,
		"cipher":         "aes-256-cbc",
	}
}

func testEncryptedDataBagSecret() []byte {
	return []byte("abcdef1234")
}

func testEncryptedDataBagVal() string {
	return "world"
}
