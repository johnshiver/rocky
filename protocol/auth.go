package protocol

import (
	"crypto/md5"
	"fmt"
	"io"
	"net"

	"github.com/johnshiver/rocky/config"
	"github.com/johnshiver/rocky/netcon"
)

func handleAuthentication(backendConfig *config.BackendHostSetting, connection net.Conn, authType int32) bool {

	switch authType {
	case AuthenticationKerberosV5:
		pLogger.Println("KerberosV5 authentication is not currently supported.")
	case AuthenticationClearText:
		pLogger.Println("Authenticating with clear text password.")
		return handleAuthClearText(connection, backendConfig.Password)
	case AuthenticationMD5:
		pLogger.Println("Authenticating with MD5 password.")
		return handleAuthMD5(connection, backendConfig.Username, backendConfig.Password)
	case AuthenticationSCM:
		pLogger.Println("SCM authentication is not currently supported.")
	case AuthenticationGSS:
		pLogger.Println("GSS authentication is not currently supported.")
	case AuthenticationGSSContinue:
		pLogger.Println("GSS authentication is not currently supported.")
	case AuthenticationSSPI:
		pLogger.Println("SSPI authentication is not currently supported.")
	case AuthenticationOk:
		/* Covers the case where the authentication type is 'cert' or 'trust' */
		return true
	default:
		pLogger.Printf("Unknown authentication method: %d\n", authType)
	}

	return false
}

func createMD5Password(username string, password string, salt string) string {
	passwordString := fmt.Sprintf("%s%s", password, username)
	passwordString = fmt.Sprintf("%x", md5.Sum([]byte(passwordString)))
	passwordString = fmt.Sprintf("%s%s", passwordString, salt)
	return fmt.Sprintf("md5%x", md5.Sum([]byte(passwordString)))
}

func handleAuthMD5(connection net.Conn, username, password string) bool {
	//  create a better salt
	salt := "THIS_IS_MY_SALT"
	password = createMD5Password(username, password, salt)

	passwordMessage := NewPasswordMessage(password)

	_, err := netcon.SendTCP(connection, passwordMessage)

	if err != nil {
		pLogger.Println("Error sending password message to the backend.")
		pLogger.Printf("Error: %s\n", err.Error())
	}

	message, _, err := netcon.ReceiveTCP(connection, 4096)

	if err != nil {
		pLogger.Println("Error receiving authentication response from the backend.")
		pLogger.Printf("Error: %s", err.Error())
	}

	return IsAuthenticationOk(message)
}

func handleAuthClearText(connection net.Conn, password string) bool {
	passwordMessage := NewPasswordMessage(password)

	_, err := connection.Write(passwordMessage)

	if err != nil {
		pLogger.Println("Error sending clear text password message to the backend.")
		pLogger.Printf("Error: %s", err.Error())
	}

	response := make([]byte, 4096)
	_, err = connection.Read(response)

	if err != nil {
		pLogger.Println("Error receiving clear text authentication response.")
		pLogger.Printf("Error: %s", err.Error())
	}

	return IsAuthenticationOk(response)
}

// This is just meant for a one off authentication of the client after it initially connects to pg_borg
// That is why the backend connection is closed at the end
// NOTE: im not sure it makes sense for the client to ever connect directly to the backend, but for now
// this works fine
func AuthenticateClient(client net.Conn, backend_host_port string, message []byte, length int) (bool, error) {
	var err error

	backend, err := netcon.ConnectTCP(backend_host_port)

	if err != nil {
		pLogger.Printf("Error connecting to %s\n", backend_host_port)
		pLogger.Printf("Error %s", err.Error())
		return false, err
	}

	defer backend.Close()

	pLogger.Printf("client auth: relay startup message to %s\n", backend_host_port)
	_, err = backend.Write(message[:length])

	pLogger.Printf("client auth: receiving startup response from %s\n", backend_host_port)
	message, length, err = netcon.ReceiveTCP(backend, 4096)

	if err != nil {
		pLogger.Println("An error occurred receiving startup response.")
		pLogger.Printf("Error %s", err.Error())
		return false, err
	}

	/*
	 While the response from the backend is not an AuthenticationOK or
	 ErrorResponse keep relaying the mesages to/from the client/backend
	*/
	messageType := GetMessageType(message)

	for !IsAuthenticationOk(message) && (messageType != ErrorMessageType) {
		netcon.SendTCP(client, message[:length])
		message, length, err = netcon.ReceiveTCP(client, 4096)

		/*
		  Must check that the client has not closed the connection.  This in
		  particular is specific to 'psql' when it prompts for a password.
		  Apparently, when psql prompts the user for a password it closes the
		  original connection, and then creates a new one. Eventually the
		  following send/receives would timeout and no 'meaningful' messages
		  are relayed. This would ultimately cause an infinite loop.  Thus it
		  is better to short circuit here if the client connection has been
		  closed.
		*/
		if (err != nil) && (err == io.EOF) {
			pLogger.Println("The client closed the connection.")
			pLogger.Println("If the client is 'psql' and the authentication method " +
				"was 'password', then this behavior is expected.")
			return false, err
		}

		netcon.SendTCP(backend, message[:length])

		message, length, err = netcon.ReceiveTCP(backend, 4096)
		messageType = GetMessageType(message)
	}

	/*
	 If the last response from the backend was AuthenticationOK, then
	 terminate the connection and return 'true' for a successful
	 authentication of the client.
	*/
	pLogger.Println("client auth: checking authentication repsonse")
	if IsAuthenticationOk(message) {
		pLogger.Println("client auth: all good!")
		termMsg := NewTerminateMessage()
		netcon.SendTCP(backend, termMsg)
		netcon.SendTCP(client, message[:length])
		return true, nil
	}

	if GetMessageType(message) == ErrorMessageType {
		pLogger.Println("Error occurred on client startup.")
	}

	netcon.SendTCP(client, message[:length])

	return false, err
}
