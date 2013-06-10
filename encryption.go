package enc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
)

const (
	cryptoHash = crypto.SHA256
)

func hash(msg *[]byte) []byte {
	h := sha256.New()
	h.Write(*msg)
	return h.Sum(nil)
}

func splitMsg(msg []byte, maxSize int) [][]byte {
	noParts := len(msg) / maxSize
	if noParts*maxSize < len(msg) {
		noParts += 1
	}

	toEncrypt := make([][]byte, noParts)
	for i, _ := range toEncrypt {
		if len(msg) > maxSize {
			toEncrypt[i] = msg[:maxSize]
			msg = msg[maxSize:]
		} else {
			toEncrypt[i] = msg
		}
	}
	return toEncrypt
}

func joinMsg(parts [][]byte) []byte {
	var buf bytes.Buffer

	for _, part := range parts {
		buf.Write(part)
	}
	return buf.Bytes()
}

type EncryptedMessage struct { //RENAME me to EncryptedMessage
	Msg [][]byte
}

func (e *EncryptedMessage) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(err.Error())
	}
	return buf.Bytes()
}

func (e *EncryptedMessage) decrypt(privateKey *rsa.PrivateKey) (signed *SignedMessage, err error) {
	hash := sha256.New()
	parts := make([][]byte, len(e.Msg))
	for i, part := range e.Msg {
		parts[i], err = rsa.DecryptOAEP(hash, rand.Reader, privateKey, part, nil)
	}
	if err != nil {
		return nil, err
	}
	wholeMsg := joinMsg(parts)

	//get signed message
	signed = new(SignedMessage)
	dec := gob.NewDecoder(bytes.NewReader(wholeMsg))
	err = dec.Decode(signed)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func (e *EncryptedMessage) DecryptAndVerify(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) (msg []byte, err error) {
	signed, err := e.decrypt(privateKey)
	if err != nil {
		return nil, err
	}

	if _, err := signed.Verify(publicKey); err != nil {
		return nil, err
	}

	//take message out
	var message Message
	dec := gob.NewDecoder(bytes.NewReader(signed.Msg))
	err = dec.Decode(&message)
	if err != nil {
		return nil, err
	}

	return message.Msg, nil
}

func (e *EncryptedMessage) DecryptToMsg(privateKey *rsa.PrivateKey) (msg []byte, err error) {
	signed, err := e.decrypt(privateKey)
	if err != nil {
		return nil, err
	}
	//take message out
	var message Message
	dec := gob.NewDecoder(bytes.NewReader(signed.Msg))
	err = dec.Decode(&message)
	if err != nil {
		return nil, err
	}

	return message.Msg, nil
}

type SignedMessage struct {
	Msg       []byte
	Signature []byte
}

func (s *SignedMessage) Verify(publicKey *rsa.PublicKey) (bool, error) {
	hashed := hash(&s.Msg)
	err := rsa.VerifyPKCS1v15(publicKey, cryptoHash, hashed, s.Signature)
	if err == nil {
		return true, nil
	}
	return false, err
}

func (s *SignedMessage) Encrypt(publicKey *rsa.PublicKey) (encrypted *EncryptedMessage, err error) {
	encrypted = new(EncryptedMessage)
	hash := sha256.New()

	//Join message and signature
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(s)
	if err != nil {
		return nil, err
	}

	//Split messages to parts acceptable by encrypter
	k := (publicKey.N.BitLen() + 7) / 8
	maxSize := k - 2*hash.Size() - 2 //from rsa.go
	toEncrypt := splitMsg(buf.Bytes(), maxSize)

	//encrypt
	parts := make([][]byte, len(toEncrypt))
	for i, part := range toEncrypt {
		parts[i], err = rsa.EncryptOAEP(hash, rand.Reader, publicKey, part, nil)
		if err != nil {
			return nil, err
		}
	}

	encrypted.Msg = parts
	return encrypted, nil
}

type Message struct {
	Msg       []byte
}

func (m *Message) SignMessage(privateKey *rsa.PrivateKey) (signed *SignedMessage, err error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(m)
	if err != nil {
		return nil, err
	}

	msg := buf.Bytes()

	signed = new(SignedMessage)
	signed.Msg = msg

	hashed := hash(&msg)

	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, cryptoHash, hashed)
	if err != nil {
		return nil, err
	}

	signed.Signature = sign
	return signed, nil
}

func SignAndEncrypt(msg []byte, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) (signedAndEncrypted *EncryptedMessage, err error) {
	message := Message{
		Msg: msg,
	}
	signedMessage, err := message.SignMessage(privateKey)
	if err != nil {
		return nil, err
	}

	encryptedMessage, err := signedMessage.Encrypt(publicKey)
	if err != nil {
		return nil, err
	}
	return encryptedMessage, nil
}
