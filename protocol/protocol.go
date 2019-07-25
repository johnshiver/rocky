// Nearly all of this came from or was modified from crunchy-proxy  Thanks guys!

/*   From the docs ------------------------------------------------------------------------------

Reference: https://www.postgresql.org/docs/9.6/static/protocol-message-formats.html
           https://www.postgresql.org/docs/9.3/static/protocol-overview.html#PROTOCOL-MESSAGE-CONCEPTS

All communication is through a stream of messages. The first byte of a message identifies the
message type, and the next four bytes specify the length of the rest of the message
(this length count includes itself, but not the message-type byte). The remaining contents of the
message are determined by the message type. For historical reasons, the very first message sent
by the client (the startup message) has no initial message-type byte.

To avoid losing synchronization with the message stream, both servers and clients typically
read an entire message into a buffer (using the byte count) before attempting to process its
contents. This allows easy recovery if an error is detected while processing the contents. In
extreme situations (such as not having enough memory to buffer the message), the receiver can use
the byte count to determine how much input to skip before it resumes reading messages.

Conversely, both servers and clients must take care never to send an incomplete message.
This is commonly done by marshaling the entire message in a buffer before beginning to send it.
If a communications failure occurs partway through sending or receiving a message, the only
sensible response is to abandon the connection, since there is little hope of recovering
message-boundary synchronization.


*/

package protocol

import (
	"bytes"
	"encoding/binary"

	"github.com/johnshiver/rocky/logger"
	"github.com/johnshiver/rocky/msgbuf"
)

const (
	// message length offsets
	PGMessageLengthOffsetStartup int   = 0
	PGMessageLengthOffset        int   = 1
	ProtocolVersion              int32 = 196608
	SSLRequestCode               int32 = 80877103

	SSLAllowed    byte = 'S'
	SSLNotAllowed byte = 'N'

	// Message Types
	AuthenticationMessageType  byte = 'R'
	ErrorMessageType           byte = 'E'
	EmptyQueryMessageType      byte = 'I'
	DescribeMessageType        byte = 'D'
	RowDescriptionMessageType  byte = 'T'
	DataRowMessageType         byte = 'D'
	QueryMessageType           byte = 'Q'
	CommandCompleteMessageType byte = 'C'
	TerminateMessageType       byte = 'X'
	NoticeMessageType          byte = 'N'
	PasswordMessageType        byte = 'p'
	ReadyForQueryMessageType   byte = 'Z'

	AuthenticationOk          int32 = 0
	AuthenticationKerberosV5  int32 = 2
	AuthenticationClearText   int32 = 3
	AuthenticationMD5         int32 = 5
	AuthenticationSCM         int32 = 6
	AuthenticationGSS         int32 = 7
	AuthenticationGSSContinue int32 = 8
	AuthenticationSSPI        int32 = 9
)

var pLogger *logger.PGLogger

func init() {
	pLogger = logger.GetLogInstance()
}

// Gets version from start up message from client
func GetVersion(message []byte) int32 {
	var code int32

	reader := bytes.NewReader(message[4:8])
	binary.Read(reader, binary.BigEndian, &code)

	pLogger.Printf("Version from start up message: %d\n", code)

	return code
}

// The first byte of the message identifies its type
func GetMessageType(message []byte) byte {
	return message[0]
}

// TODO: this appears to fail when transmitting larger responses from the backend
// The 4 bytes after the message identify the message length
func GetMessageLength(message []byte) int32 {
	var messageLength int32

	reader := bytes.NewReader(message[1:5])
	binary.Read(reader, binary.BigEndian, &messageLength)

	return messageLength
}

func IsAuthenticationOk(message []byte) bool {
	if GetMessageType(message) != AuthenticationMessageType {
		return false
	}

	var messageValue int32

	// Get the message length.
	messageLength := GetMessageLength(message)

	// Get the message value.
	reader := bytes.NewReader(message[5:9])
	binary.Read(reader, binary.BigEndian, &messageValue)

	return (messageLength == 8 && messageValue == AuthenticationOk)
}

func GetTerminateMessage() []byte {
	var buffer []byte
	buffer = append(buffer, 'X')

	//make msg len 1 for now
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(4))
	buffer = append(buffer, x...)
	return buffer
}

func CreatePasswordMessage(password string) []byte {
	message := msgbuf.New([]byte{})

	// Set the message type
	message.WriteByte(PasswordMessageType)

	// Initialize the message length to zero.
	message.WriteInt32(0)

	// Add the password to the message.
	message.WriteString(password)

	// Update the message length
	message.ResetLength(PGMessageLengthOffset)

	return message.Bytes()
}

// CreateStartupMessage creates a PG startup message. This message is used to
// startup all connections with a PG backend.
func CreateStartupMessage(username string, database string, options map[string]string) []byte {
	message := msgbuf.New([]byte{})
	// Temporarily set the message length to 0.
	message.WriteInt32(0)
	message.WriteInt32(ProtocolVersion)

	/*
	  The protocol version number is followed by one or more pairs of
	  parameter name and value strings. A zero byte is required as a
	  terminator after the last name/value pair. Parameters can appear in any
	  order. 'user' is required, others are optional.
	*/

	// Set the 'user' parameter.  This is the only *required* parameter.
	message.WriteString("user")
	message.WriteString(username)

	message.WriteString("database")
	message.WriteString(database)

	/* Set the remaining options as specified. */
	for option, value := range options {
		message.WriteString(option)
		message.WriteString(value)
	}

	// The message should end with a NULL byte
	message.WriteByte(0x00)
	message.ResetLength(PGMessageLengthOffsetStartup)

	return message.Bytes()
}

func parseStartUpResponse(message []byte) (int32, int32) {
	var msgLength int32
	var authType int32

	reader := bytes.NewReader(message[1:5])
	binary.Read(reader, binary.BigEndian, &msgLength)

	reader.Reset(message[5:9])
	binary.Read(reader, binary.BigEndian, &authType)
	return msgLength, authType

}
