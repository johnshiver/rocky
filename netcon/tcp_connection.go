package netcon

import (
	"net"

	"github.com/johnshiver/rocky/logger"
)

var pLogger *logger.PGLogger

func init() {
	pLogger = logger.GetLogInstance()
}

// Send
//
// Sends bytes to TCP connection
func SendTCP(connection net.Conn, message []byte) (int, error) {
	return connection.Write(message)
}

// Receive
//
// return buffer of bytes, length of buffer, error
func ReceiveTCP(connection net.Conn, bufferSize int) ([]byte, int, error) {
	buffer := make([]byte, bufferSize)
	length, err := connection.Read(buffer)
	return buffer, length, err
}

// ConnectTCP
//
// Given a host string, returns a tcp connection if successful, otherwise returns an error
func ConnectTCP(host string) (net.Conn, error) {
	// will fail if host doesnt resolve
	getResolvedAddress(host)
	connection, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

// getResolvedAddresses
//
// Takes a host string and returns a TCPAddr which can be used to
// establish TCP connection with DialTCP
//
// tcpAddr := getResolvedAddress("127.0.0.1:8080")
//
func getResolvedAddress(host string) *net.TCPAddr {
	var addr *net.TCPAddr
	addr, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {
		pLogger.Fatal(err)
	}
	return addr
}

func GetListener(addr *net.TCPAddr) *net.TCPListener {
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		pLogger.Fatal(err)
	}
	return listener
}
