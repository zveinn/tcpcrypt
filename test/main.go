package main

import (
	"fmt"
	"net"
	"time"

	tcpcrypt "github.com/zveinn/tcpcrypt"
)

func main() {
	go newClient()
	newListener("9999")
}

func newListener(port string) {
	L1, err := net.Listen("tcp", "0.0.0.0:"+port)
	fmt.Println(err)
	for {
		conn, err := L1.Accept()
		if err != nil {
			fmt.Println(err)
			time.Sleep(1 * time.Millisecond)
			continue
		}
		go handleSocket(conn)
	}
}

func handleSocket(conn net.Conn) {
	T, err := tcpcrypt.NewSocketWrapper(conn, tcpcrypt.AES256)
	if err != nil {
		fmt.Println("error making new wrapper for server ", err)
		return
	}

	err = T.ReceiveHandshake()
	if err != nil {
		fmt.Println("error receiving", err)
		return
	}
	fmt.Println("SERVER KEY:", T.SEAL.Key)

	for {
		_, decryptedData, control, err := T.Read()
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("FROM CLIENT >> ")
		fmt.Println(string(decryptedData))
		fmt.Println(decryptedData)
		fmt.Println("CONTROL:", control)
	}
}

func newClient() {
	time.Sleep(2 * time.Second)
	C1, err := net.Dial("tcp", "0.0.0.0:9999")
	if err != nil {
		fmt.Println("CANT DIAL!", err)
	}

	T, err := tcpcrypt.NewSocketWrapper(C1, tcpcrypt.AES256)
	if err != nil {
		fmt.Println("error making new wrapper for client ", err)
		return
	}

	err = T.InitHandshake()
	if err != nil {
		fmt.Println("error on init", err)
		return
	}
	fmt.Println("CLIENT KEY:", T.SEAL.Key)

	data := []byte("HELLO THIS IS ENCRYPTED FROM THE CLIENT HELLO THIS IS ENCRYPTED FROM THE CLIENT !!")

	for {
		time.Sleep(1 * time.Second)
		_, err = T.Write(data, [2]byte{111, 111})
		if err != nil {
			fmt.Println(err)
		}
	}
}
