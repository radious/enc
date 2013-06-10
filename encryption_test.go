package enc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func generateKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err.Error())
	}
	return key
}

func TestSigning(t *testing.T) {
	key1 := generateKey(t)

	message := new(Message)
	s := "Foo Bar"
	message.Msg = []byte(s)

	signedMsg, err := message.SignMessage(key1)
	if err != nil {
		t.Fatal(err.Error())
	}

	eval, err := signedMsg.Verify(&key1.PublicKey)
	if err != nil {
		t.Fatal(err.Error())
	} else if eval != true {
		t.Fatal("Public keys doesn't match!")
	}

	/*	if err != nil {
		t.Fatal(err.Error())
	}*/
}

func TestSplitting(t *testing.T) {
	m := "Zażółć gęślą jaźć. Lorem Ipsum. Foo Bar."
	msg := []byte(m)
	splitBy := 3

	splitted := splitMsg(msg, 3)
	for _, s := range splitted {
		if len(s) > splitBy {
			t.Error("Too long", s)
		}
	}

	joined := joinMsg(splitted)
	if string(joined) != m {
		t.Error("Strings not equal!", "\n", m, "\n", string(joined))
	}
}

func TestEncrypting(t *testing.T) {
	key1 := generateKey(t)
	key2 := generateKey(t)
	msg := []byte("Taka tam wiadomość")

	signedAndEncrypted, err := SignAndEncrypt(msg, key1, &key2.PublicKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	msgRec, err := signedAndEncrypted.DecryptAndVerify(key2, &key1.PublicKey)
	if err != nil || len(msgRec) == 0 {
		t.Fatal(err.Error())
	}

	if len(msgRec) != len(msg) {
		t.Fatal("Messages has different sizes!", len(msgRec), "!=", len(msg))
	}

	for i := 0; i < len(msg); i += 1 {
		if msg[i] != msgRec[i] {
			t.Fatalf("Char %v is different in messages!", i)
		}
	}
}
