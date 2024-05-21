package tcpcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type EncType int

const (
	None EncType = iota
	AES128
	AES192
	AES256
	CHACHA20
)

type SEAL struct {
	Created    time.Time
	Key        []byte
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
	AEAD       cipher.AEAD
	Nonce      []byte
	NonceInt   uint64
	Type       EncType
}

func (S *SEAL) CreateAEAD() (err error) {
	if S.Type == None {
	} else if S.Type == AES256 || S.Type == AES128 || S.Type == AES192 {

		if S.Type == AES128 {
			S.Key = S.Key[:16]
		} else if S.Type == AES192 {
			S.Key = S.Key[:24]
		}

		CB, CBErr := aes.NewCipher(S.Key)
		if CBErr != nil {
			err = CBErr
			return
		}

		S.AEAD, err = cipher.NewGCM(CB)
		if err != nil {
			return
		}

		S.Nonce = make([]byte, S.AEAD.NonceSize())

	} else if S.Type == CHACHA20 {

		S.AEAD, err = chacha20poly1305.NewX(S.Key)
		if err != nil {
			return
		}
		S.Nonce = make([]byte, S.AEAD.NonceSize())
	}

	return
}

func (S *SEAL) Encrypt(data []byte) []byte {
	return S.AEAD.Seal(nil, S.Nonce, data, nil)
}

func (S *SEAL) Decrypt(data []byte) (decrypted []byte, err error) {
	decrypted, err = S.AEAD.Open(nil, S.Nonce, data, nil)
	return
}

func (S *SEAL) ECDH() (err error) {
	var nk []byte
	nk, err = S.PrivateKey.ECDH(S.PublicKey)
	sk := sha256.Sum256(nk)
	S.Key = sk[:]
	return
}

func (S *SEAL) PublicKeyFromBytes(publicKey []byte) (err error) {
	S.PublicKey, err = ecdh.P521().NewPublicKey(publicKey)
	if err != nil {
		return
	}
	return
}

func NewPrivateKey() (PK *ecdh.PrivateKey, err error) {
	PK, err = ecdh.P521().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	return
}

func NewPublicKeyFromBytes(b []byte) (PK *ecdh.PublicKey, err error) {
	PK, err = ecdh.P521().NewPublicKey(b)
	if err != nil {
		return
	}
	return
}

type SocketWrapper struct {
	SOCKET   net.Conn
	LocalPK  *ecdh.PrivateKey
	RemotePK *ecdh.PublicKey
	SEAL     *SEAL

	// This buffer will be populated with the outgoing
	// encrypted data
	outBuffer [66000]byte
	outData   []byte
	control   [2]byte
	// outLen    int

	// ...
	encryptedReceiver [66000]byte
	decryptedReceiver [66000]byte
	inLen             uint16
}

func NewSocketWrapper(
	SOCKET net.Conn,
	encryptionType EncType,
) (T *SocketWrapper, err error) {
	T = new(SocketWrapper)
	T.SOCKET = SOCKET
	T.SEAL = new(SEAL)
	T.SEAL.Created = time.Now()
	T.SEAL.Type = encryptionType
	T.SEAL.PrivateKey, err = NewPrivateKey()
	return
}

func (T *SocketWrapper) InitHandshake() (err error) {
	err = T.sendPublicKey()
	if err != nil {
		return
	}
	err = T.receivePublicKey()
	if err != nil {
		return
	}
	err = T.computeSharedKey()
	if err != nil {
		return
	}
	err = T.SEAL.CreateAEAD()
	return
}

func (T *SocketWrapper) ReceiveHandshake() (err error) {
	err = T.receivePublicKey()
	if err != nil {
		return
	}
	err = T.sendPublicKey()
	if err != nil {
		return
	}
	err = T.computeSharedKey()
	if err != nil {
		return
	}
	err = T.SEAL.CreateAEAD()
	return
}

func (T *SocketWrapper) Read() (n int, outputBuffer []byte, control [2]byte, err error) {
	fmt.Println("INGRESS__________________________________")
	_, err = io.ReadAtLeast(
		T.SOCKET,
		T.encryptedReceiver[0:12],
		12,
	)
	fmt.Println("1.BUFF:", T.encryptedReceiver[0:12])
	if err != nil {
		fmt.Println("first read")
		return
	}

	T.inLen = binary.BigEndian.Uint16(T.encryptedReceiver[0:2])
	fmt.Println("LEN:", T.inLen)
	n, err = io.ReadAtLeast(
		T.SOCKET,
		T.encryptedReceiver[12:T.inLen+12],
		int(T.inLen),
	)

	fmt.Println("2.BUFF:", T.encryptedReceiver[12:T.inLen+12])
	if err != nil {
		fmt.Println("second read")
		return
	}

	T.encryptedReceiver[0] = 0
	T.encryptedReceiver[1] = 0
	control[0] = T.encryptedReceiver[2]
	control[1] = T.encryptedReceiver[3]

	fmt.Println("NONCE:", T.encryptedReceiver[0:12])
	outputBuffer, err = T.SEAL.AEAD.Open(
		T.decryptedReceiver[:0],
		T.encryptedReceiver[0:12],
		T.encryptedReceiver[12:T.inLen+12],
		nil,
	)

	// fmt.Println("NONCE:", T.SEAL.Nonce)
	// fmt.Println("N:", n)
	// fmt.Println("Tin:", T.inLen)
	// fmt.Println("lout:", len(outputBuffer))
	// fmt.Println("pp:", &outputBuffer[0])
	// fmt.Println("pp:", &T.decryptedReceiver[0])
	// fmt.Println("pp:", &T.encryptedReceiver[0])
	// fmt.Println("_____________________________________-")
	return
}

func (T *SocketWrapper) Write(data []byte, control [2]byte) (n int, err error) {
	T.outBuffer[0] = 0
	T.outBuffer[1] = 0
	T.outBuffer[2] = control[0]
	T.outBuffer[3] = control[1]

	fmt.Println("_____________________________________-")
	fmt.Println("XX:")
	T.SEAL.NonceInt++
	binary.BigEndian.PutUint64(T.outBuffer[4:12], T.SEAL.NonceInt)
	fmt.Println("NONCE:", T.outBuffer[:12])

	T.outData = T.SEAL.AEAD.Seal(
		T.outBuffer[:12],
		T.outBuffer[:12],
		data,
		nil,
	)

	binary.BigEndian.PutUint16(T.outData[0:2], uint16(len(T.outData)-12))

	fmt.Println(&T.outBuffer[0])
	fmt.Println(T.outBuffer[0:12])
	fmt.Println(&T.outData[0])
	fmt.Println(T.outData[0:12], "-", len(T.outData))
	fmt.Println(binary.BigEndian.Uint16(T.outData[0:2]))
	fmt.Println(T.outData)
	fmt.Println("_____________________________________-")
	n, err = T.SOCKET.Write(T.outData)
	return
}

func (T *SocketWrapper) computeSharedKey() (err error) {
	return T.SEAL.ECDH()
}

func (T *SocketWrapper) sendPublicKey() (err error) {
	defer func() {
		r := recover()
		if r != nil {
			log.Println(r, string(debug.Stack()))
		}
		_ = T.SOCKET.SetWriteDeadline(time.Time{})
	}()

	KT := T.SEAL.PrivateKey.PublicKey().Bytes()
	OUT := make([]byte, 2)
	binary.BigEndian.PutUint16(OUT[0:2], uint16(len(KT)))
	var n int
	_ = T.SOCKET.SetWriteDeadline(time.Now().Add(time.Second * 10))
	n, err = T.SOCKET.Write(append(OUT, KT...))
	if n != len(KT)+2 {
		return errors.New("bytes written did not equal the length of the public key")
	}
	return
}

func (T *SocketWrapper) receivePublicKey() (err error) {
	defer func() {
		r := recover()
		if r != nil {
			log.Println(r, string(debug.Stack()))
		}
		_ = T.SOCKET.SetReadDeadline(time.Time{})
	}()

	LB := make([]byte, 2)
	_ = T.SOCKET.SetReadDeadline(time.Now().Add(time.Second * 10))
	n, err := T.SOCKET.Read(LB)
	if err != nil {
		return
	}
	if n != 2 {
		return errors.New("did not read two bytes")
	}
	KL := binary.BigEndian.Uint16(LB)
	PublicKey := make([]byte, KL)
	n, err = T.SOCKET.Read(PublicKey)
	if err != nil {
		return
	}
	if n != int(KL) {
		return errors.New("did not read all the public key bytes")
	}

	T.SEAL.PublicKey, err = NewPublicKeyFromBytes(PublicKey)
	return
}
