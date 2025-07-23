package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "time"
)

// Enterprise encryption with multiple key support
type EnterpriseEncryption struct {
    masterKey []byte
    userKeys  map[string][]byte // userID -> encryption key
    keyRotationInterval time.Duration
}

type EncryptedFile struct {
    UserID       string
    EncryptedKey []byte // User's key encrypted with master key
    IV           []byte
    Data         []byte
    Signature    []byte
    Timestamp    time.Time
}

func NewEnterpriseEncryption(masterKey []byte) *EnterpriseEncryption {
    return &EnterpriseEncryption{
        masterKey: masterKey,
        userKeys:  make(map[string][]byte),
        keyRotationInterval: 24 * time.Hour, // Rotate daily
    }
}

func (ee *EnterpriseEncryption) GenerateUserKey(userID string) error {
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return err
    }
    ee.userKeys[userID] = key
    return nil
}

func (ee *EnterpriseEncryption) EncryptForUser(userID string, data []byte) (*EncryptedFile, error) {
    userKey, exists := ee.userKeys[userID]
    if !exists {
        return nil, fmt.Errorf("user key not found for user: %s", userID)
    }

    block, err := aes.NewCipher(userKey)
    if err != nil {
        return nil, err
    }

    iv := make([]byte, block.BlockSize())
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCTR(block, iv)
    encrypted := make([]byte, len(data))
    stream.XORKeyStream(encrypted, data)

    // Encrypt user key with master key for key escrow
    encryptedUserKey, err := ee.encryptWithMasterKey(userKey)
    if err != nil {
        return nil, err
    }

    // Create signature for integrity
    signature := ee.createSignature(encrypted, userID)

    return &EncryptedFile{
        UserID:       userID,
        EncryptedKey: encryptedUserKey,
        IV:           iv,
        Data:         encrypted,
        Signature:    signature,
        Timestamp:    time.Now(),
    }, nil
}

func (ee *EnterpriseEncryption) encryptWithMasterKey(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(ee.masterKey)
    if err != nil {
        return nil, err
    }

    iv := make([]byte, block.BlockSize())
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCTR(block, iv)
    encrypted := make([]byte, len(data))
    stream.XORKeyStream(encrypted, data)

    // Prepend IV
    result := make([]byte, len(iv)+len(encrypted))
    copy(result, iv)
    copy(result[len(iv):], encrypted)
    
    return result, nil
}

func (ee *EnterpriseEncryption) createSignature(data []byte, userID string) []byte {
    hash := sha256.New()
    hash.Write(data)
    hash.Write([]byte(userID))
    hash.Write(ee.masterKey)
    return hash.Sum(nil)
}

func (ee *EnterpriseEncryption) DecryptForUser(userID string, encFile *EncryptedFile) ([]byte, error) {
    userKey, exists := ee.userKeys[userID]
    if !exists {
        return nil, fmt.Errorf("user key not found for user: %s", userID)
    }

    // Verify signature
    expectedSignature := ee.createSignature(encFile.Data, userID)
    if hex.EncodeToString(expectedSignature) != hex.EncodeToString(encFile.Signature) {
        return nil, fmt.Errorf("signature verification failed")
    }

    block, err := aes.NewCipher(userKey)
    if err != nil {
        return nil, err
    }

    stream := cipher.NewCTR(block, encFile.IV)
    decrypted := make([]byte, len(encFile.Data))
    stream.XORKeyStream(decrypted, encFile.Data)

    return decrypted, nil
}
