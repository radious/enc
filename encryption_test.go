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
	message.Msg = []byte(lorem)

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

func TestDecrypting(t *testing.T) {
	key1 := generateKey(t)
	key2 := generateKey(t)
	msg := []byte(lorem)

	encryptedMessage, err := SignAndEncrypt(msg, key1, &key2.PublicKey)
	if err != nil {
		t.Fatal(err.Error())
	}

	encrypted := encryptedMessage.Bytes()

	decrypted, err := Decrypt(encrypted, key2)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(decrypted) != len(msg) {
		t.Fatal("Messages has different sizes!", len(decrypted), "!=", len(msg))
	}

	for i := 0; i < len(msg); i += 1 {
		if msg[i] != decrypted[i] {
			t.Fatalf("Char %v is different in messages!", i)
		}
	}
}

const (
	lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed hendrerit lectus eu sapien dictum cursus. Duis fermentum tempus ligula et luctus. Vestibulum sit amet libero quis sapien consequat ultricies ut non sapien. Nam eu lectus hendrerit, venenatis nulla vitae, dignissim lectus. Cras urna tellus, ullamcorper vel neque at, elementum ullamcorper nisi. Quisque laoreet est turpis, ut tincidunt urna ullamcorper non. Duis euismod pellentesque turpis, a viverra arcu ullamcorper vitae. Interdum et malesuada fames ac ante ipsum primis in faucibus. Suspendisse vulputate ante eu iaculis luctus. Maecenas eget cursus est. Nullam dictum velit eu massa elementum, sit amet gravida urna luctus. Praesent aliquam lobortis sagittis. Aliquam pharetra semper viverra. Phasellus aliquet euismod orci, non ullamcorper tellus sollicitudin sed. Aliquam sed auctor ipsum. Aliquam sed porttitor sem. In vehicula diam sit amet quam cursus, volutpat tincidunt dolor interdum. Donec pellentesque molestie rhoncus. Proin quis mi iaculis, consequat lectus vitae, sollicitudin nulla. Donec quis tellus elit. In vel nulla orci. Mauris volutpat viverra ante, vel laoreet justo auctor quis. Quisque mattis, nunc ut convallis accumsan, nulla justo lobortis purus, nec elementum massa massa id justo. Maecenas molestie ligula at turpis posuere, ut imperdiet lorem mollis. Donec et nibh in erat sagittis blandit. Vivamus sed mauris nec justo pulvinar porta. Nunc posuere sed enim eu sodales. Vivamus dignissim commodo erat vehicula condimentum. In non lorem in mi pulvinar mollis ac varius ligula. Suspendisse auctor dictum pulvinar. Suspendisse non risus non lectus euismod aliquet. Nunc feugiat sapien nisl. Suspendisse sed hendrerit sem. Aliquam viverra placerat ipsum et vestibulum. Vivamus interdum, erat nec luctus pretium, nisl dolor suscipit leo, vel malesuada leo quam sed massa. Praesent in turpis in tellus hendrerit ultrices. Vivamus volutpat sem quis egestas convallis. Etiam mattis nibh dui, id auctor ligula ultricies et. Ut tempor interdum pulvinar. Interdum et malesuada fames ac ante ipsum primis in faucibus. Vestibulum feugiat nec sapien ac porttitor. Integer tristique elementum dolor, id dignissim lacus vulputate vel. Mauris volutpat sodales laoreet. Curabitur eleifend dolor vitae fermentum vehicula. Maecenas quis ipsum eu dui hendrerit mollis. Vestibulum placerat lorem sit amet enim laoreet accumsan. Phasellus vel sapien erat. Fusce luctus eros ut orci adipiscing aliquet vitae sollicitudin ligula. Etiam non varius sapien. Integer eget mauris et arcu tempor accumsan a ut dui. Sed accumsan eget massa vitae consequat. Sed sagittis, libero eu pharetra hendrerit, massa magna luctus est, sed blandit elit elit vel lorem. Aliquam erat volutpat. Nulla sed dictum nisl. Nam iaculis massa sit amet dignissim pharetra. Aliquam eget posuere risus, non consequat nisi. Quisque rhoncus augue lectus, ac cursus enim posuere commodo. Curabitur lobortis neque eget tellus placerat, ut elementum elit adipiscing. Nunc sit amet dictum urna. Etiam vehicula sem libero, ut placerat nulla lobortis eget. Ut condimentum tellus sit amet ligula tempus convallis. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Sed tortor mi, molestie eu tempor sit amet, lobortis vestibulum tellus. Integer nec scelerisque est. Aliquam lobortis nisi nec sapien mollis, id hendrerit turpis tincidunt. Donec lobortis, mi id mattis fringilla, mauris mauris scelerisque turpis, sit amet gravida lectus magna et nibh. In tincidunt justo vel rutrum viverra. Pellentesque non ipsum nec sem pulvinar eleifend. Fusce tempor ligula fermentum quam posuere mattis. Pellentesque at vulputate justo. Integer accumsan, nisl ut pharetra fermentum, lorem dolor tincidunt sem, id dignissim libero velit id massa. Cras et pharetra nunc. Vivamus at leo malesuada mauris blandit fermentum ut vitae erat. Nulla non sapien eget tellus dignissim consectetur. Donec accumsan, elit a laoreet tempus, justo eros ultricies quam, id cursus diam sapien in sapien. Ut a purus suscipit, pellentesque dui nec, hendrerit risus. Morbi ac sagittis elit. Nunc mattis vulputate consectetur. Integer a tempor justo. Donec sem sem, accumsan in ullamcorper eget, tincidunt at sapien. Vestibulum laoreet turpis vel orci auctor, eget elementum turpis posuere. Vestibulum adipiscing arcu pellentesque, varius orci non, ultrices quam. In hac habitasse platea dictumst. Nunc ut augue lectus. Etiam imperdiet neque eu arcu blandit, id tincidunt urna semper. Mauris eu risus nulla. Mauris vel tincidunt ligula. Aliquam quis congue neque, vitae tempor mi. Ut mollis mollis turpis in tempus. Duis eleifend augue imperdiet odio congue, ut pellentesque est cursus. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vivamus a urna placerat, ornare sapien gravida, euismod arcu. Pellentesque porttitor elit nibh, sit amet porttitor libero pellentesque quis. Proin porttitor eleifend orci, at suscipit nunc. Nulla malesuada leo sed lectus fermentum lobortis. Suspendisse nec rutrum turpis, id malesuada erat. In imperdiet posuere massa. Aliquam vulputate sit amet odio eget ultrices. Donec vel laoreet ante, varius posuere eros. Morbi non quam convallis diam ultrices malesuada. Quisque quis tincidunt quam, eu suscipit mauris. Ut euismod purus libero, sed sodales enim semper nec. Fusce pretium dui et pulvinar adipiscing. Phasellus ipsum augue, rutrum vel elit at, elementum ullamcorper enim. Proin dictum vehicula libero, ac sollicitudin enim bibendum quis. Morbi lorem lorem, tristique a tempus at, feugiat eget erat. Proin varius consectetur erat vel suscipit. In sit amet rhoncus quam, non aliquet massa. Pellentesque at consectetur lectus. Donec eget odio at risus scelerisque posuere sit amet ac tellus. Etiam porta erat nec justo pellentesque, eu posuere sem pharetra. Phasellus iaculis tempus lobortis. Proin mattis eleifend dolor a dapibus. Phasellus id viverra turpis. Nullam semper varius mollis. Donec a nunc vel mauris congue tincidunt non quis tellus. Praesent diam diam, posuere et nisi ut, dapibus dictum risus. Cras eu enim non dui facilisis facilisis. Nunc lacus augue, gravida faucibus congue et, adipiscing in justo. Vestibulum sit amet est vel elit faucibus convallis. Mauris pellentesque massa leo. Proin mattis, quam hendrerit bibendum sollicitudin, eros nisl accumsan felis, sit amet placerat augue diam id dui. Nullam eu metus condimentum, sollicitudin eros quis, semper metus. Pellentesque tempus accumsan dolor ut tincidunt. Proin facilisis sem vitae ipsum pulvinar accumsan. Morbi ac lobortis ante. Etiam erat augue, faucibus non nisl porttitor, congue porta neque. Sed sed elit nec sapien eleifend rutrum. Proin ultricies sapien at justo iaculis, sed lobortis lectus aliquam. Donec odio ante, faucibus id nulla vel, tincidunt interdum eros. Aenean diam neque, malesuada vel elit et, lacinia pharetra erat. Vivamus id dictum risus. Ut ullamcorper ante sed lectus euismod, vitae."
)
