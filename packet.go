package gomqtt

import (
	"errors"
	"reflect"
	"strings"
)

// Protocol name to place in the variable header of the CONNECT control packet.
const Protocol = "MQTT"

// Version of protocol to place in the variable header of the CONNECT control packet.
const Version = 4

// MaxPacketSize is the maximum size of a control packet.
const MaxPacketSize = 1 << 28

// Common error strings
var (
	// Unmarshal
	ErrPacketType     = errors.New("Unknown MQTT Control Packet type")
	ErrLengthMismatch = errors.New("Encoded Remaining Length is different from actual remaining length of packet")

	// decodeRemLength
	ErrRemLengthTooLarge = errors.New("Encoded Remaining Length exceeded maximum value")

	// decodeUInt16
	ErrDecodeUInt16 = errors.New("Byte slice too small to decode uint16")

	// decodeString
	ErrRequiredString = errors.New("Required string is missing from packet")
	ErrDecodeString   = errors.New("Byte slice too small to decode string")
)

// CONNECTFlags errors
var (
	ErrCFlagsReserved = errors.New("Reserved flag in Connect Flags must be set to 0")
	ErrConnectFlags   = errors.New("Incorrect Connect Flags found in CONNECT packet")
)

// CONNECT errors
var (
	ErrCONNECTFlags       = errors.New("Invalid flags for CONNECT packet")
	ErrProtocolName       = errors.New("Invalid protocol name in CONNECT packet")
	ErrProtocolLevel      = errors.New("Invalid protocol version in CONNECT packet")
	ErrKeepAlive          = errors.New("Invalid Keep Alive in CONNECT packet")
	ErrMissingClientID    = errors.New("Missing Client ID in CONNECT packet")
	ErrWillTopicMissing   = errors.New("Will Topic missing from CONNECT packet")
	ErrWillMessageMissing = errors.New("Will Message missing from CONNECT packet")
	ErrUsernameMissing    = errors.New("Username missing from CONNECT packet")
	ErrPasswordMissing    = errors.New("Password missing from CONNECT packet")
	ErrCONNECT            = errors.New("Unknown extra data encoded in CONNECT packet")
)

// CONNACK errors
var (
	ErrCONNACKFlags      = errors.New("Invalid flags for CONNACK packet")
	ErrCAckFlags         = errors.New("Connect Acknowledge Flags bits 7-1 must be set to 0 in CONNACK packet")
	ErrCONNACKReturnCode = errors.New("Invalid Return Code in CONNACK packet")
	ErrCONNACK           = errors.New("Unknown extra data encoded in CONNACK packet")
)

// PUBLISH errors
var (
	ErrPUBLISHInvalidQoS      = errors.New("Invalid QoS value in PUBLISH packet")
	ErrMissingTopicName       = errors.New("Missing Topic Name from PUBLISH packet")
	ErrTopicName              = errors.New("Invalid Topic Name in PUBLISH packet")
	ErrPUBLISHPacketID        = errors.New("Packet ID missing in PUBLISH packet")
	ErrPUBLISHInvalidPacketID = errors.New("Packet ID in PUBLISH packet must be non-zero")
	ErrPUBLISH                = errors.New("Unknown extra data encoded in PUBLISH packet")
)

// PUBACK errors
var (
	ErrPUBACKFlags           = errors.New("Invalid flags for PUBACK packet")
	ErrPUBACKExpectedSize    = errors.New("Invalid expected packet size for PUBACK packet")
	ErrPUBACKInvalidPacketID = errors.New("Packet ID in PUBACK packet must be non-zero")
)

// PUBREC errors
var (
	ErrPUBRECFlags           = errors.New("Invalid flags for PUBREC packet")
	ErrPUBRECExpectedSize    = errors.New("Invalid expected packet size for PUBREC packet")
	ErrPUBRECInvalidPacketID = errors.New("Packet ID in PUBREC packet must be non-zero")
)

// PUBREL errors
var (
	ErrPUBRELFlags           = errors.New("Invalid flags for PUBREL packet")
	ErrPUBRELExpectedSize    = errors.New("Invalid expected packet size for PUBREL packet")
	ErrPUBRELInvalidPacketID = errors.New("Packet ID in PUBREL packet must be non-zero")
)

// PUBCOMP errors
var (
	ErrPUBCOMPFlags           = errors.New("Invalid flags for PUBCOMP packet")
	ErrPUBCOMPExpectedSize    = errors.New("Invalid expected packet size for PUBCOMP packet")
	ErrPUBCOMPInvalidPacketID = errors.New("Packet ID in PUBCOMP packet must be non-zero")
)

// SUBSCRIBE errors
var (
	ErrSUBSCRIBEFlags              = errors.New("Invalid flags for SUBSCRIBE packet")
	ErrSUBSCRIBEPacketID           = errors.New("Packet ID missing in SUBSCRIBE packet")
	ErrSUBSCRIBEInvalidPacketID    = errors.New("Packet ID in SUBSCRIBE packet must be non-zero")
	ErrSUBSCRIBEPair               = errors.New("SUBSCRIBE packet must contain at least one topic filter / qos pair")
	ErrSUBSCRIBEMissingTopicFilter = errors.New("Missing Topic Filter in SUBSCRIBE packet")
	ErrSUBSCRIBEInvalidTopicFilter = errors.New("Invalid Topic Filter in SUBSCRIBE packet")
	ErrMissingQoS                  = errors.New("Missing paired QoS value in SUBSCRIBE packet")
	ErrReservedQoS                 = errors.New("Reserved bits in Requested QoS byte must be set to 0 in SUBSCRIBE packet")
	ErrSUBSCRIBEInvalidQoS         = errors.New("Invalid QoS value in SUBSCRIBE packet")
	ErrSUBSCRIBE                   = errors.New("Unknown extra data encoded in SUBSCRIBE packet")
)

// SUBACK errors
var (
	ErrSUBACKFlags      = errors.New("Invalid flags for SUBACK packet")
	ErrSUBACKPacketID   = errors.New("Packet ID missing in SUBACK packet")
	ErrSUBACKReturnCode = errors.New("Invalid Return Code in SUBACK packet")
	ErrSUBACK           = errors.New("Unknown extra data encoded in SUBACK packet")
)

// UNSUBSCRIBE errors
var (
	ErrUNSUBSCRIBEFlags              = errors.New("Invalid flags for UNSUBSCRIBE packet")
	ErrUNSUBSCRIBEPacketID           = errors.New("Packet ID missing in UNSUBSCRIBE packet")
	ErrUNSUBSCRIBEInvalidPacketID    = errors.New("Packet ID in UNSUBSCRIBE packet must be non-zero")
	ErrUNSUBSCRIBEMissingTopicFilter = errors.New("Missing Topic Filter in UNSUBSCRIBE packet")
	ErrUNSUBSCRIBEInvalidTopicFilter = errors.New("Invalid Topic Filter in SUBSCRIBE packet")
	ErrUNSUBSCRIBETopicFilter        = errors.New("UNSUBSCRIBE packet must contain at least one topic filter")
	ErrUNSUBSCRIBE                   = errors.New("Unknown extra data encoded in UNSUBSCRIBE packet")
)

// UNSUBACK errors
var (
	ErrUNSUBACKFlags           = errors.New("Invalid flags for UNSUBACK packet")
	ErrUNSUBACKExpectedSize    = errors.New("Invalid expected packet size for UNSUBACK packet")
	ErrUNSUBACKInvalidPacketID = errors.New("Packet ID in UNSUBACK packet must be non-zero")
)

// PINGREQ errors
var (
	ErrPINGREQFlags        = errors.New("Invalid flags for PINGREQ packet")
	ErrPINGREQExpectedSize = errors.New("Invalid expected packet size for PINGREQ packet")
)

// PINGRESP errors
var (
	ErrPINGRESPFlags        = errors.New("Invalid flags for PINGRESP packet")
	ErrPINGRESPExpectedSize = errors.New("Invalid expected packet size for PINGRESP packet")
)

// DISCONNECT errors
var (
	ErrDISCONNECTFlags        = errors.New("Invalid flags for DISCONNECT packet")
	ErrDISCONNECTExpectedSize = errors.New("Invalid expected packet size for DISCONNECT packet")
)

const (
	ErrPacketIDQoSZero  = "Packet must not contain Packet Identifier with QoS 0"
	ErrUsernamePresent  = "Username found in CONNECT packet even though flag is missing"
	ErrPasswordPresent  = "Password found in CONNECT packet even though flag is missing"
	ErrPasswordUsername = "Password found in CONNECT packet even though username flag is missing"
	ErrInvalidClientID  = "Client Identifier invalid in CONNECT packet payload"
)

// The different MQTT Control Packet Types found in the first
// 4 bits of the first byte of a control packet.
const (
	TypeCONNECT     byte = iota + 1 // 1
	TypeCONNACK                     // 2
	TypePUBLISH                     // 3
	TypePUBACK                      // 4
	TypePUBREC                      // 5
	TypePUBREL                      // 6
	TypePUBCOMP                     // 7
	TypeSUBSCRIBE                   // 8
	TypeSUBACK                      // 9
	TypeUNSUBSCRIBE                 // 10
	TypeUNSUBACK                    // 11
	TypePINGREQ                     // 12
	TypePINGRESP                    // 13
	TypeDISCONNECT                  // 14
)

// The different MQTT Control Packet Flags found in the last
// 4 bits of the first byte of a control packet.
//
// Note: The PUBLISH packet has variable Flags.
const (
	FlagsCONNECT     byte = 0
	FlagsCONNACK          = 0
	FlagsPUBACK           = 0
	FlagsPUBREC           = 0
	FlagsPUBREL           = 2
	FlagsPUBCOMP          = 0
	FlagsSUBSCRIBE        = 2
	FlagsSUBACK           = 0
	FlagsUNSUBSCRIBE      = 2
	FlagsUNSUBACK         = 0
	FlagsPINGREQ          = 0
	FlagsPINGRESP         = 0
	FlagsDISCONNECT       = 0
)

// Quality of Service possible values:
//
// Defined in Section 3.3.1.2 of the specification.
type QoSValue byte

const (
	AtMostOnce  QoSValue = iota // 0
	AtLeastOnce                 // 1
	ExactlyOnce                 // 2
)

// ControllerPacket is the interface implemented by the MQTT control packets.
type ControllerPacket interface {

	// Marshal converts a control packet into its byte representation
	// in accordance with the MQTT specification.
	Marshal() []byte

	// Type returns the type of the MQTT control packet.
	Type() byte

	// Flags returns the flags of the MQTT control packet.
	Flags() byte
}

// unmarshaler is the interface implemented by all of the MQTT control packets
// in this file.
// They allow to unmarshal packets only using the variable header and payload.
type unmarshaler interface {
	ControllerPacket
	unmarshal([]byte) error
}

// Unmarshal converts the byte slice into one of the MQTT control packets.
func Unmarshal(b []byte) (ControllerPacket, error) {

	// Each control packet has a unique type, specific flags, and the remaining
	// length of the packet (which doesn't include the fixed header).
	//
	// Defined in Section 2.2 of the specification.

	// The first byte of the packet contains the MQTT control packet type
	// and the MQTT control packet flags.
	var pktType byte = b[0] >> 4
	var pktFlags byte = b[0] & 0x0f

	// The following bytes are the encoded Remaining Length of the packet.
	remLen, used, err := decodeRemLength(b)
	if err != nil {
		return nil, err
	}

	// Validate that the encoded remaining length equals the actual remaining
	// length of the packet

	// Unmarshal the remaining byte slice according to the decoded packet type.
	// The remaining byte slice contains the rest of the packet without the
	// fixed header (i.e. it only contains the variable header and payload
	// when applicable).

	// Variable And Payload
	var VAP []byte = b[1+used:]
	// Validate that the remLen equals the actual remaining length
	if remLen != len(VAP) {
		return nil, ErrLengthMismatch
	}

	//var pkt ControllerPacket
	var pkt unmarshaler
	var validFlags bool
	var errFlags error
	switch pktType {
	case TypeCONNECT:
		pkt = &CONNECT{}
		validFlags = FlagsCONNECT == pktFlags
		errFlags = ErrCONNECTFlags
	case TypeCONNACK:
		pkt = &CONNACK{}
		validFlags = FlagsCONNACK == pktFlags
		errFlags = ErrCONNACKFlags
	case TypePUBLISH:
		qos := QoSValue((b[0] >> 1) & 0x3)
		if qos == 3 {
			return nil, ErrPUBLISHInvalidQoS
		}
		pkt = &PUBLISH{
			DUP:    (b[0] & 0x8) != 0,
			QoS:    qos,
			RETAIN: (b[0] & 0x1) != 0,
		}
		validFlags = true
	case TypePUBACK:
		pkt = &PUBACK{}
		validFlags = FlagsPUBACK == pktFlags
		errFlags = ErrPUBACKFlags
	case TypePUBREC:
		pkt = &PUBREC{}
		validFlags = FlagsPUBREC == pktFlags
		errFlags = ErrPUBRECFlags
	case TypePUBREL:
		pkt = &PUBREL{}
		validFlags = FlagsPUBREL == pktFlags
		errFlags = ErrPUBRELFlags
	case TypePUBCOMP:
		pkt = &PUBCOMP{}
		validFlags = FlagsPUBCOMP == pktFlags
		errFlags = ErrPUBCOMPFlags
	case TypeSUBSCRIBE:
		pkt = &SUBSCRIBE{}
		validFlags = FlagsSUBSCRIBE == pktFlags
		errFlags = ErrSUBSCRIBEFlags
	case TypeSUBACK:
		pkt = &SUBACK{}
		validFlags = FlagsSUBACK == pktFlags
		errFlags = ErrSUBACKFlags
	case TypeUNSUBSCRIBE:
		pkt = &UNSUBSCRIBE{}
		validFlags = FlagsUNSUBSCRIBE == pktFlags
		errFlags = ErrUNSUBSCRIBEFlags
	case TypeUNSUBACK:
		pkt = &UNSUBACK{}
		validFlags = FlagsUNSUBACK == pktFlags
		errFlags = ErrUNSUBACKFlags
	case TypePINGREQ:
		pkt = &PINGREQ{}
		validFlags = FlagsPINGREQ == pktFlags
		errFlags = ErrPINGREQFlags
	case TypePINGRESP:
		pkt = &PINGRESP{}
		validFlags = FlagsPINGRESP == pktFlags
		errFlags = ErrPINGRESPFlags
	case TypeDISCONNECT:
		pkt = &DISCONNECT{}
		validFlags = FlagsDISCONNECT == pktFlags
		errFlags = ErrDISCONNECTFlags
	default: // Unknown Packet Type
		return nil, ErrPacketType
	}

	// Error if the MQTT Control Packet flags do not match
	if !validFlags {
		return nil, errFlags
	}

	// Call the unmarshal(VAP) function of the packet
	err = pkt.unmarshal(VAP)
	if err != nil {
		return nil, err
	}

	return pkt.(ControllerPacket), nil
}

/*
// fixedHeader is the fixed header part of each control packet.
//
// Each control packet has a unique type, specific flags, and the remaining
// length of the packet (which doesn't include the fixed header).
//
// Defined in Section 2.2 of the specification.
type fixedHeader struct {
	Type   int
	Flags  int
	RemLen int
}
*/

// addFixedHeader adds the fixed header to the control packet.
func addFixedHeader(pkt ControllerPacket, marshaled []byte) []byte {
	remLen := encodeRemLength(len(marshaled))

	length := 1 + len(remLen) + len(marshaled)

	// Complete Packet contains the first byte (i.e. Packet Type & Packet Flags)
	// followed by the Remaining Length of the packet, and finally the variable
	// header and payload of the control packet.
	completePkt := make([]byte, 0, length)
	completePkt = append(completePkt, byte((pkt.Type()<<4)|(pkt.Flags()&0xf)))
	completePkt = append(completePkt, remLen...)
	completePkt = append(completePkt, marshaled...)

	return completePkt
}

/*
// extractFixedHeader extracts the FixedHeader from a complete control packet
// (fixed, variable, and payload) byte slice, returning the remainging bytes
// of the packet without the fixed header.
func extractFixedHeader(completePkt []byte) (fixedHeader, []byte, error) {
	fh := fixedHeader{}
	if len(completePkt) == 0 {
		return fh, nil, ErrEmptyPacket
	}
	fh.Type = int(completePkt[0] >> 4)
	fh.Flags = int(completePkt[0] & 0xf)
	remLen, bytesUsed, err := decodeRemLength(completePkt)
	if err != nil {
		return fh, nil, err
	}
	fh.RemLen = remLen

	// Compare Remaining Length versus actual remaining length of packet
	if remLen != len(completePkt[1+bytesUsed:]) {
		return fh, nil, ErrRemLengthMismatch
	}

	return fh, completePkt[1+bytesUsed:], nil
}
*/

// CONNECTFlags represents the connect flags in the variable header of the
// CONNECT control packet.
//
// Defined in Section 3.1.2.3 of the specification.
type CONNECTFlags struct {
	CleanSession bool
	WillFlag     bool
	WillQoS      QoSValue
	WillRetain   bool
	PasswordFlag bool
	UserNameFlag bool
}

// marshalCFlags marshals CONNECTFLags into a single byte used in the
// CONNECT control packet.
func marshalCFlags(cf CONNECTFlags) byte {
	var encoded byte
	if cf.CleanSession {
		encoded = encoded | (1 << 1)
	}
	if cf.WillFlag {
		encoded = encoded | (1 << 2)
	}
	encoded = encoded | byte((cf.WillQoS&0x3)<<3)
	if cf.WillRetain {
		encoded = encoded | (1 << 5)
	}
	if cf.PasswordFlag {
		encoded = encoded | (1 << 6)
	}
	if cf.UserNameFlag {
		encoded = encoded | (1 << 7)
	}
	return encoded
}

// unmarshalCFlags unmarshals CONNECTFlags from a single byte retrieved
// in a CONNECT control packet.
// TODO: Create targeted error messages
func unmarshalCFlags(b byte) (CONNECTFlags, error) {
	cf := CONNECTFlags{}

	// The Server MUST validate that the reserved flag in the
	// CONNECT Control Packet is set to zero and disconnect the Client
	// if it is not zero [MQTT-3.1.2-3].
	if b&0x01 != 0 {
		return cf, ErrCFlagsReserved
	}

	cf.CleanSession = (b & (1 << 1)) > 0
	cf.WillFlag = (b & (1 << 2)) > 0
	cf.WillQoS = QoSValue((b >> 3) & 0x3)
	cf.WillRetain = (b & (1 << 5)) > 0
	cf.PasswordFlag = (b & (1 << 6)) > 0
	cf.UserNameFlag = (b & (1 << 7)) > 0

	// If the Will Flag is set to 0, the Will QoS and Will Retain fields in the
	// Connect Flags MUST be set to zero and the Will Topic and Will Message
	// fields MUST NOT be present in the payload [MQTT-3.1.2-11].
	if !cf.WillFlag {
		if cf.WillQoS != 0 || cf.WillRetain {
			return cf, ErrConnectFlags
		}
	}

	// If the Will Flag is set to 0,
	// then the Will QoS MUST be set to 0 (0x00) [MQTT-3.1.2-13].
	//
	// If the Will Flag is set to 1, the value of Will QoS can be 0 (0x00),
	// 1 (0x01), or 2 (0x02). It MUST NOT be 3 (0x03) [MQTT-3.1.2-14].
	//
	// If the Will Flag is set to 0,
	// then the Will Retain Flag MUST be set to 0 [MQTT-3.1.2-15].
	if !cf.WillFlag {
		if cf.WillQoS != 0 {
			return cf, ErrConnectFlags
		}
		if cf.WillRetain {
			return cf, ErrConnectFlags
		}
	} else {
		if cf.WillQoS == 0x03 {
			return cf, ErrConnectFlags
		}
	}

	// If the User Name Flag is set to 0,
	// the Password Flag MUST be set to 0 [MQTT-3.1.2-22].
	if !cf.UserNameFlag {
		if cf.PasswordFlag {
			return cf, ErrConnectFlags
		}
	}

	return cf, nil
}

// CONNECT is a control packet used by clients to request a
// connection to a server.
//
// The CONNECT packet contains the following as part of its variable header:
//  - protocol name: "MQTT"
//  - protocol level: 4
//  - connect flags:
//    + Bit 0: Reserved
//    + Bit 1: Clean Session
//    + Bit 2: Will Flag
//    + Bit 3-4: Will QoS
//    + Bit 5: Will Retain
//    + Bit 6: Password
//    + Bit 7: User Name
//  - keep alive: how long a communication should be kept alive
//
// The payload of the CONNECT packet contains a Client Identifier used to
// identify a unique client to the server. If the Will Flag is set in the
// connect flags, then a Will Topic and a Will Message are provided next in
// the payload. Finally, a Username and/or Password will be in the payload
// according to the User Name flag and Password flag in the connect flags,
// respectively. Therefore, only the Client Identifier is required in the
// payload, the other values are optional.
//
// Defined in Section 3.1 of the specification.
type CONNECT struct {
	CFlags      CONNECTFlags
	KeepAlive   uint16
	ClientID    string
	WillTopic   string
	WillMessage string
	Username    string
	Password    string
}

// Marshal converts the CONNECT control packet into its byte slice representation.
func (pkt *CONNECT) Marshal() []byte {
	marshaled := make([]byte, 0)

	// Protocol
	marshaled = append(marshaled, encodeString(Protocol)...)
	// Version
	marshaled = append(marshaled, Version)
	// Connect Flags
	marshaled = append(marshaled, marshalCFlags(pkt.CFlags))
	// Keep Alive
	marshaled = append(marshaled, encodeUInt16(pkt.KeepAlive)...)
	// Client ID
	marshaled = append(marshaled, encodeString(pkt.ClientID)...)
	// Will Topic
	// append([]byte, nil...) is a noop
	marshaled = append(marshaled, encodeString(pkt.WillTopic)...)
	// Will Message
	marshaled = append(marshaled, encodeString(pkt.WillMessage)...)
	// Username
	marshaled = append(marshaled, encodeString(pkt.Username)...)
	// Password
	marshaled = append(marshaled, encodeString(pkt.Password)...)
	// Fixed Header
	marshaled = addFixedHeader(pkt, marshaled)

	return marshaled
}

// unmarshal populates the CONNECT control packet from the VAP.
func (pkt *CONNECT) unmarshal(VAP []byte) error {
	var protocol, clientID, willTopic, willMsg, username, password string
	var version int
	var keepAlive uint16
	var bytes []byte
	var err error
	// Protocol
	protocol, bytes, err = decodeString(VAP, true)
	if protocol != Protocol {
		return ErrProtocolName
	}
	// Version
	version = int(bytes[0])
	if version != Version {
		return ErrProtocolLevel
	}
	// Connect Flags
	cflags, err := unmarshalCFlags(bytes[1])
	if err != nil {
		return err
	}
	pkt.CFlags = cflags
	// Keep Alive
	keepAlive, bytes, err = decodeUInt16(bytes[2:])
	if err != nil {
		return concatErrors(ErrKeepAlive, err)
	}
	pkt.KeepAlive = keepAlive
	// Client ID
	// The Client Identifier (ClientId) MUST be present and MUST be the first
	// field in the CONNECT packet payload [MQTT-3.1.3-3].
	// The ClientId MUST be a UTF-8 encoded string as defined in Section 1.5.3 [MQTT-3.1.3-4].
	// The Server MUST allow ClientIds which are between 1 and 23 UTF-8 encoded
	// bytes in length, and that contain only the characters: [0-9a-zA-Z] [MQTT-3.1.3-5].
	clientID, bytes, err = decodeString(bytes, true)
	if err != nil {
		return concatErrors(ErrMissingClientID, err)
	}
	// TODO: Validate Client Identifier
	// TODO: Think about [MQTT-3.1.3-6] and [MQTT-3.1.3-7]
	pkt.ClientID = clientID
	// Will Topic & Will Message
	// If the Will Flag is set to 1, the Will Topic is the next field in the payload.
	// The Will Topic MUST be a UTF-8 encoded string as defined in Section 1.5.3 [MQTT-3.1.3-10].
	// If the Will Flag is set to 1, the Will Message is the next field in the payload. (Section 3.1.3.3)
	if cflags.WillFlag {
		willTopic, bytes, err = decodeString(bytes, true)
		if err != nil {
			return concatErrors(ErrWillTopicMissing, err)
		}
		pkt.WillTopic = willTopic

		willMsg, bytes, err = decodeString(bytes, true)
		if err != nil {
			return concatErrors(ErrWillMessageMissing, err)
		}
		pkt.WillMessage = willMsg
	}
	// Username
	// If the User Name Flag is set to 0, a user name MUST NOT be present
	// in the payload [MQTT-3.1.2-18].
	// If the User Name Flag is set to 1, a user name MUST be present in
	// the payload [MQTT-3.1.2-19].
	// If the User Name Flag is set to 1, this is the next field in the payload.
	// The User Name MUST be a UTF-8 encoded string as defined in Section 1.5.3 [MQTT-3.1.3-11].
	if cflags.UserNameFlag {
		username, bytes, err = decodeString(bytes, true)
		if err != nil {
			return concatErrors(ErrUsernameMissing, err)
		}
		pkt.Username = username
	}
	// Password
	// If the Password Flag is set to 0, a password MUST NOT be present in the
	// payload [MQTT-3.1.2-20].
	// If the Password Flag is set to 1, a password MUST be present in the payload [MQTT-3.1.2-22].
	if cflags.PasswordFlag {
		password, bytes, err = decodeString(bytes, true)
		if err != nil {
			return concatErrors(ErrPasswordMissing, err)
		}
		pkt.Password = password
	}
	// If there is data left, then this is an invalid CONNECT packet
	if len(bytes) != 0 {
		return ErrCONNECT
	}

	return nil
}

// Type will return the type of the CONNECT control packet.
func (pkt *CONNECT) Type() byte {
	return TypeCONNECT
}

// Flags will return the flags of the CONNECT control packet.
func (pkt *CONNECT) Flags() byte {
	return FlagsCONNECT
}

// CONNACK is a response control packet to acknowledge connection requests.
//
// The variable header of the CONNACK control packet contains the
// Connect Acknowledge Flags and the connection Return Code.
// There is currently only a single flag being used, the Session Present Flag.
// This tells a client if a session already existed on this server.
// The following table represents the possible values for this return code:
//  |-------|---------------------------------|--------------------------------|
//  | Value | Return Code Response            | Description                    |
//  |-------|---------------------------------|--------------------------------|
//  | 0     | 0x00: Connection Accepted       | Connection accepted            |
//  |-------|---------------------------------|--------------------------------|
//  | 1     | 0x01: Connection Refused,       | The Server does not support the|
//  |       | unacceptable protocol version   | level of the MQTT protocol     |
//  |       |                                 | requested by the client        |
//  |-------|---------------------------------|--------------------------------|
//  | 2     | 0x02: Connection Refused,       | The Client identifier is       |
//  |       | identifier rejected             | correct UTF-8 but not allowed  |
//  |       |                                 | by the server                  |
//  |-------|---------------------------------|--------------------------------|
//  | 3     | 0x03: Connection Refused,       | The Network Connection has been|
//  |       | server unavailable              | made but the MQTT service is   |
//  |       |                                 | unavailable                    |
//  |-------|---------------------------------|--------------------------------|
//  | 4     | 0x04: Connection Refused,       | The data in the user name or   |
//  |       | bad user name or password       | or password is malformed       |
//  |-------|---------------------------------|--------------------------------|
//  | 5     | 0x05: Connection Refused,       | The Client is not authorized   |
//  |       | not authorized                  | to connect                     |
//  |-------|---------------------------------|--------------------------------|
//  | 6-255 |                                 | Reserved for future use        |
//  |-------|---------------------------------|--------------------------------|
//
// The CONNACK packet has no payload.
//
// Defined in Section 3.2 of the specification.
type CONNACK struct {
	SessionPresent bool
	ReturnCode     byte
}

// Marshal converts the CONNACK control packet into its byte slice representation.
func (pkt *CONNACK) Marshal() []byte {
	marshaled := make([]byte, 2)

	// Connect Acknowledgement Flags
	if pkt.SessionPresent {
		marshaled[0] = 1
	} else {
		marshaled[0] = 0
	}
	// Return Code
	marshaled[1] = byte(pkt.ReturnCode)
	// Fixed Header
	marshaled = addFixedHeader(pkt, marshaled)

	return marshaled
}

// unmarshal populates the CONNACK control packet from the VAP.
func (pkt *CONNACK) unmarshal(VAP []byte) error {
	// Expected remaining length
	if len(VAP) != 2 {
		return ErrCONNACK
	}
	// Connect Acknowledge Flags
	// Bits 7-1 are reserved and MUST be set to 0.
	if VAP[0]&0xfe != 0 {
		return ErrCAckFlags
	}
	pkt.SessionPresent = (VAP[0]&0x01 == 1)
	// Return code
	if VAP[1] >= 6 {
		return ErrCONNACKReturnCode
	}
	pkt.ReturnCode = VAP[1]

	return nil
}

// Type will return the type of the CONNACK control packet.
func (pkt *CONNACK) Type() byte {
	return TypeCONNACK
}

// Flags will return the flags of the CONNACK control packet.
func (pkt *CONNACK) Flags() byte {
	return FlagsCONNACK
}

// PUBLISH is a control packet to publish messages.
//
// The flags in the fixed header are:
//  - DUP (bit 3): whether this is a duplicate of a message that
//    the sending party has already sent.
//  - QoS level (bits 2-1): level of assurance for delivery of the application message.
//  - RETAIN (bit 0): whether the application message in this packet should be retained
//    so that future subscriptions receive this message.
// The QoS level is defined according to this table:
//  |-----------|-------|-------|----------------------------------------------|
//  | QoS value | Bit 2 | Bit 1 | Description                                  |
//  |-----------|-------|-------|----------------------------------------------|
//  |     0     |   0   |   0   | At most once delivery                        |
//  |-----------|-------|-------|----------------------------------------------|
//  |     1     |   0   |   1   | At least once delivery                       |
//  |-----------|-------|-------|----------------------------------------------|
//  |     2     |   1   |   0   | Exactly once delivery                        |
//  |-----------|-------|-------|----------------------------------------------|
//  |     -     |   1   |   1   | Reserved - must not be used                  |
//  |-----------|-------|-------|----------------------------------------------|
//
// The variable header of the PUBLISH packet contains a Topic Name as the
// destination for this application message and a Packet Identifier to identify
// this packet and acknowledgments for this packet.
//
// The payload contains the application message.
//
// Defined in Section 3.3 of the specification.
type PUBLISH struct {
	DUP       bool
	QoS       QoSValue
	RETAIN    bool
	TopicName string
	PacketID  uint16
	Message   []byte
}

// Marshal converts the PUBLISH control packet into its byte slice representation.
func (pkt *PUBLISH) Marshal() []byte {
	marshaled := make([]byte, 0)

	// Topic Name
	marshaled = append(marshaled, encodeString(pkt.TopicName)...)
	// Packet ID
	marshaled = append(marshaled, encodeUInt16(pkt.PacketID)...)
	// Fixed Header
	marshaled = addFixedHeader(pkt, marshaled)
	// PUBLISH control packet has special Flags
	marshaled[0] |= byte(pkt.QoS << 1)
	if pkt.DUP {
		marshaled[0] |= (1 << 3)
	}
	if pkt.RETAIN {
		marshaled[0] |= 1
	}

	return marshaled
}

// unmarshal populates the PUBLISH control packet from the VAP.
func (pkt *PUBLISH) unmarshal(VAP []byte) error {
	var topicName string
	var packetID uint16
	var bytes []byte
	var err error
	// Topic Name
	// The Topic Name MUST be present as the first field in the
	// PUBLISH Packet Variable header. It MUST be a UTF-8 encoded string [MQTT-3.3.2-1]
	// The Topic Name in the PUBLISH Packet MUST NOT contain wildcard characters [MQTT-3.3.2-2].
	topicName, bytes, err = decodeString(VAP, true)
	if err != nil {
		return ErrMissingTopicName
	}
	if !IsValidTopicName(topicName) {
		return ErrTopicName
	}
	pkt.TopicName = topicName
	// Packet ID
	// PUBLISH (in cases where QoS > 0) Control Packet MUST contain a non-zero
	// 16-bit Packet Identifier [MQTT-2.3.1-1]
	if pkt.QoS > 0 {
		packetID, bytes, err = decodeUInt16(bytes)
		if err != nil {
			return ErrPUBLISHPacketID
		}
		if packetID == 0 {
			return ErrPUBLISHInvalidPacketID
		}
		pkt.PacketID = packetID
	}

	// Application Message
	pkt.Message = bytes

	return nil
}

// Type will return the type of the PUBLISH control packet.
func (pkt *PUBLISH) Type() byte {
	return TypePUBLISH
}

// Flags will return the flags of the PUBLISH control packet.
func (pkt *PUBLISH) Flags() byte {
	var flags byte = byte(pkt.QoS) << 1
	if pkt.DUP {
		flags |= (1 << 3)
	}
	if pkt.RETAIN {
		flags |= 1
	}
	return flags
}

// PUBACK is a response control packet to acknowledge a PUBLISH packet
// with QoS level 1.
//
// The variable header of the PUBACK packet contains only a Packet Identifier
// taken from the PUBLISH packet being acknowledged.
//
// The PUBACK packet has no payload.
//
// Defined in Section 3.4 of the specification.
type PUBACK struct {
	PacketID uint16
}

// Marshal converts the PUBACK control packet into its byte slice representation.
func (pkt *PUBACK) Marshal() []byte {
	return pubMarshal(pkt)
}

// unmarshal populates the PUBACK control packet from the VAP.
func (pkt *PUBACK) unmarshal(VAP []byte) error {
	return pubUnmarshal(pkt, VAP)
}

// Type will return the type of the PUBACK control packet.
func (pkt *PUBACK) Type() byte {
	return TypePUBACK
}

// Flags will return the flags of the PUBACK control packet.
func (pkt *PUBACK) Flags() byte {
	return FlagsPUBACK
}

// PUBREC is a response control packet to a PUBLISH packet with QoS level 2.
// This is the 2nd packet of the QoS 2 protocol exchange.
//
// The variable header of the PUBREC packet contains only a Packet Identifier
// taken from the PUBLISH packet being acknowledged.
//
// The PUBREC packet has no payload.
//
// Defined in Section 3.5 of the specification.
type PUBREC struct {
	PacketID uint16
}

// Marshal converts the PUBREC control packet into its byte slice representation.
func (pkt *PUBREC) Marshal() []byte {
	return pubMarshal(pkt)
}

// unmarshal populates the PUBREC control packet from the VAP.
func (pkt *PUBREC) unmarshal(VAP []byte) error {
	return pubUnmarshal(pkt, VAP)
}

// Type will return the type of the PUBREC control packet.
func (pkt *PUBREC) Type() byte {
	return TypePUBREC
}

// Flags will return the flags of the PUBREC control packet.
func (pkt *PUBREC) Flags() byte {
	return FlagsPUBREC
}

// PUBREL is a response control packet to a PUBREC packet.
// This is the 3rd packet of the QoS 2 protocol exchange.
//
// The variable header of the PUBREL packet contains only a Packet Identifier
// taken from the PUBREC packet being acknowledged.
//
// The PUBREL packet has no payload.
//
// Defined in Section 3.6 of the specification.
type PUBREL struct {
	PacketID uint16
}

// Marshal converts the PUBREL control packet into its byte slice representation.
func (pkt *PUBREL) Marshal() []byte {
	return pubMarshal(pkt)
}

// unmarshal populates the PUBREL control packet from the VAP.
func (pkt *PUBREL) unmarshal(VAP []byte) error {
	return pubUnmarshal(pkt, VAP)
}

// Type will return the type of the PUBREL control packet.
func (pkt *PUBREL) Type() byte {
	return TypePUBREL
}

// Flags will return the flags of the PUBREL control packet.
func (pkt *PUBREL) Flags() byte {
	return FlagsPUBREL
}

// PUBCOMP is a response control packet to a PUBREL packet.
// This is the 4th and final packet of the QoS 2 protocol exchange.
//
// The variable header of the PUBCOMP packet contains only a Packet Identifier
// taken from the PUBREL packet being acknowledged.
//
// The PUBCOMP packet has no payload.
//
// Defined in Section 3.7 of the specification.
type PUBCOMP struct {
	PacketID uint16
}

// Marshal converts the PUBCOMP control packet into its byte slice representation.
func (pkt *PUBCOMP) Marshal() []byte {
	return pubMarshal(pkt)
}

// unmarshal populates the PUBCOMP control packet from the VAP.
func (pkt *PUBCOMP) unmarshal(VAP []byte) error {
	/*fh, bytes, err := extractFixedHeader(b)
	if err != nil {
		return unmarshalError("PUBCOMP", err.Error())
	}

	// Validate fixedHeader for PUBCOMP packet
	if fh.ptype != TypePUBCOMP {
		return unmarshalError("PUBCOMP", "Invalid PUBCOMP packet type")
	}
	if fh.pflags != FlagsPUBCOMP {
		return unmarshalError("PUBCOMP", "Invalid PUBCOMP packet flags")
	}
	if fh.remLen != 2 {
		return unmarshalError("PUBCOMP", "Invalid PUBCOMP packet length")
	}

	// Packet ID
	packetID, bytes, err := decodeInt(bytes)
	if err != nil {
		return unmarshalError("PUBCOMP", err.Error())
	}
	pkt.pktID = uint16(packetID)

	return nil*/
	/*controlPkt, err := pubUnmarshal(TypePUBCOMP, FlagsPUBCOMP, b)
	pkt := controlPkt.(*PUBCOMP)
	return pkt, err*/
	return pubUnmarshal(pkt, VAP)
}

// Type will return the type of the PUBCOMP control packet.
func (pkt *PUBCOMP) Type() byte {
	return TypePUBCOMP
}

// Flags will return the flags of the PUBCOMP control packet.
func (pkt *PUBCOMP) Flags() byte {
	return FlagsPUBCOMP
}

// TopicQosPair is a pair of Topic Filter and QoS level contained in the payload
// of a SUBSCRIBE control packet.
//
// Defined in Section 3.8.3 of the specification.
type TopicQoSPair struct {
	TopicFilter string
	QoS         QoSValue
}

// SUBSCRIBE is a control packet to subscribe to topics.
//
// The variable header of the SUBSCRIBE packet contains only a
// Packet Identifier.
//
// The payload contains a list of Topic Filters matching a Topic Name paired
// with a requested QoS level that the client wishes to subscribe to.
//
// Defined in Section 3.8 of the specification.
type SUBSCRIBE struct {
	PacketID uint16
	TQPairs  []TopicQoSPair
}

// Marshal converts the SUBSCRIBE control packet into its byte slice representation.
func (pkt *SUBSCRIBE) Marshal() []byte {
	marshaled := make([]byte, 0)

	// Packet ID
	marshaled = append(marshaled, encodeUInt16(pkt.PacketID)...)
	// Topic Filter/QoS Pairs
	for _, tqPair := range pkt.TQPairs {
		marshaled = append(marshaled, encodeString(tqPair.TopicFilter)...)
		marshaled = append(marshaled, byte(tqPair.QoS&0x3))
	}
	// Fixed Header
	marshaled = addFixedHeader(pkt, marshaled)

	return marshaled
}

// unmarshal populates the SUBSCRIBE control packet from the VAP.
func (pkt *SUBSCRIBE) unmarshal(VAP []byte) error {
	// Packet ID
	// SUBSCRIBE Control Packet MUST contain a non-zero
	// 16-bit Packet Identifier [MQTT-2.3.1-1]
	packetID, bytes, err := decodeUInt16(VAP)
	if err != nil {
		return ErrSUBSCRIBEPacketID
	}
	if packetID == 0 {
		return ErrSUBSCRIBEInvalidPacketID
	}
	pkt.PacketID = packetID
	// Topic Filter/QoS Pairs
	// The Topic Filters in a SUBSCRIBE packet payload MUST be UTF-8 encoded
	// strings as defined in Section 1.5.3 [MQTT-3.8.3-1].
	// The payload of a SUBSCRIBE packet MUST contain at least one Topic Filter /
	// QoS pair. A SUBSCRIBE packet with no payload is a protocol violation [MQTT-3.8.3-3].
	//
	// The requested maximum QoS field is encoded in the byte following each
	// UTF-8 encoded topic name, and these Topic Filter / QoS pairs are packed
	// contiguously. The upper 6 bits of the Requested QoS byte are not used in
	// the current version of the protocol. They are reserved for future use.
	// The Server MUST treat a SUBSCRIBE packet as malformed and close the
	// Network Connection if any of Reserved bits in the payload are non-zero,
	// or QoS is not 0,1 or 2 [MQTT-3.8.3-4].
	if len(bytes) == 0 {
		return ErrSUBSCRIBEPair
	}
	pkt.TQPairs = make([]TopicQoSPair, 0)
	var tqPair TopicQoSPair
	var topicFilter string
	var firstTopicFilter bool = true
	for len(bytes) > 0 {
		// Topic Filter
		if firstTopicFilter {
			topicFilter, bytes, err = decodeString(bytes, true)
			firstTopicFilter = false
		} else {
			topicFilter, bytes, err = decodeString(bytes, false)
		}
		if err != nil {
			return ErrSUBSCRIBEMissingTopicFilter
		}
		if !IsValidTopicFilter(topicFilter) {
			return ErrSUBSCRIBEInvalidTopicFilter
		}
		// QoS
		if len(bytes) == 0 {
			return ErrMissingQoS
		}
		if bytes[0]&0xf6 == 0 {
			return ErrReservedQoS
		}
		qos := bytes[0] & 0x3
		if qos == 3 {
			return ErrSUBSCRIBEInvalidQoS
		}
		tqPair = TopicQoSPair{
			TopicFilter: topicFilter,
			QoS:         QoSValue(qos),
		}
		pkt.TQPairs = append(pkt.TQPairs, tqPair)
	}

	return nil
}

// Type will return the type of the SUBSCRIBE control packet.
func (pkt *SUBSCRIBE) Type() byte {
	return TypeSUBSCRIBE
}

// Flags will return the flags of the SUBSCRIBE control packet.
func (pkt *SUBSCRIBE) Flags() byte {
	return FlagsSUBSCRIBE
}

// SUBACK is a response control packet to acknowledge a SUBSCRIBE packet.
//
// The variable header of a SUBACK packet contains only a Packet Identifier
// taken from the SUBSCRIBE packet being acknowledged.
//
// The payload contains a list of return codes for each Topic Filter/QoS pair
// from the corresponding SUBSCRIBE packet.
// The return code values are according to this table:
//  |------|---------|------------------------|
//  | Code | Result  | Description            |
//  |------|---------|------------------------|
//  | 0x00 | Success | Maximum QoS 0          |
//  |------|---------|------------------------|
//  | 0x01 | Success | Maximum QoS 1          |
//  |------|---------|------------------------|
//  | 0x02 | Sucess  | Maximum QoS 2          |
//  |------|---------|------------------------|
//  | 0x80 | Failure |                        |
//  |------|---------|------------------------|
//
// Defined in Section 3.9 of the specification.
type SUBACK struct {
	PacketID    uint16
	ReturnCodes []byte
}

// Marshal converts the SUBACK control packet into its byte slice representation.
func (pkt *SUBACK) Marshal() []byte {
	marshaled := make([]byte, 0)

	// Packet ID
	marshaled = append(marshaled, encodeUInt16(pkt.PacketID)...)
	// Return Codes
	for _, rc := range pkt.ReturnCodes {
		marshaled = append(marshaled, byte(rc))
	}
	// Fixed Header
	marshaled = addFixedHeader(pkt, marshaled)

	return marshaled
}

// unmarshal populates the SUBACK control packet from the VAP.
func (pkt *SUBACK) unmarshal(VAP []byte) error {
	// Packet ID
	packetID, bytes, err := decodeUInt16(VAP)
	if err != nil {
		return ErrSUBACKPacketID
	}
	pkt.PacketID = packetID
	// Return Codes
	// SUBACK return codes other than 0x00, 0x01, 0x02 and 0x80 are reserved
	// and MUST NOT be used [MQTT-3.9.3-2].
	pkt.ReturnCodes = make([]byte, 0, len(bytes))
	var code byte
	for _, rc := range bytes {
		if (rc & 0x7c) != 0 {
			return ErrSUBACKReturnCode
		}
		code = rc & 0x83
		if code != 0x00 && code != 0x01 && code != 0x02 && code != 0x80 {
			return ErrSUBACKReturnCode
		}
		pkt.ReturnCodes = append(pkt.ReturnCodes, code)
	}

	return nil
}

// Type will return the type of the SUBACK control packet.
func (pkt *SUBACK) Type() byte {
	return TypeSUBACK
}

// Flags will return the flags of the SUBACK control packet.
func (pkt *SUBACK) Flags() byte {
	return FlagsSUBACK
}

// UNSUBSCRIBE is a control packet used to unsubscribe from topics.
//
// The variable header of the UNSUBSCRIBE packet contains only a
// Packet Identifier.
//
// The payload contains a list of Topic Filters that the client wishes to
// unsubscribe from.
//
// Defined in Section 3.10 of the specification.
type UNSUBSCRIBE struct {
	PacketID     uint16
	TopicFilters []string
}

// Marshal converts the UNSUBSCRIBE control packet into its byte slice representation.
func (pkt *UNSUBSCRIBE) Marshal() []byte {
	marshaled := make([]byte, 0)

	// Packet ID
	marshaled = append(marshaled, encodeUInt16(pkt.PacketID)...)
	// Topic Filters
	for _, tf := range pkt.TopicFilters {
		marshaled = append(marshaled, encodeString(tf)...)
	}
	// Fixed Header
	marshaled = addFixedHeader(pkt, marshaled)

	return marshaled
}

// unmarshal populates the UNSUBSCRIBE control packet from the VAP.
func (pkt *UNSUBSCRIBE) unmarshal(VAP []byte) error {
	// Packet ID
	// UNSUBSCRIBE Control Packet MUST contain a non-zero
	// 16-bit Packet Identifier [MQTT-2.3.1-1]
	packetID, bytes, err := decodeUInt16(VAP)
	if err != nil {
		return ErrUNSUBSCRIBEPacketID
	}
	if packetID == 0 {
		return ErrUNSUBSCRIBEInvalidPacketID
	}
	pkt.PacketID = packetID
	// Topic Filters
	// The Topic Filters in an UNSUBSCRIBE packet MUST be UTF-8 encoded strings
	// as defined in Section 1.5.3, packed contiguously [MQTT-3.10.3.-1].
	//
	// The Payload of an UNSUBSCRIBE packet MUST contain at least one Topic Filter.
	// An UNSUBSCRIBE packet with no payload is a protocol violation [MQTT-3.10.3-2].
	if len(bytes) == 0 {
		return ErrUNSUBSCRIBETopicFilter
	}
	pkt.TopicFilters = make([]string, 0)
	var topicFilter string
	var firstTopicFilter bool = true
	for len(bytes) > 0 {
		// Topic Filter
		if firstTopicFilter {
			topicFilter, bytes, err = decodeString(bytes, true)
			firstTopicFilter = false
		} else {
			topicFilter, bytes, err = decodeString(bytes, false)
		}
		if err != nil {
			return ErrUNSUBSCRIBEMissingTopicFilter
		}
		if !IsValidTopicFilter(topicFilter) {
			return ErrUNSUBSCRIBEInvalidTopicFilter
		}
		pkt.TopicFilters = append(pkt.TopicFilters, topicFilter)
	}

	return nil
}

// Type will return the type of the UNSUBSCRIBE control packet.
func (pkt *UNSUBSCRIBE) Type() byte {
	return TypeUNSUBSCRIBE
}

// Flags will return the flags of the UNSUBSCRIBE control packet.
func (pkt *UNSUBSCRIBE) Flags() byte {
	return FlagsUNSUBSCRIBE
}

// UNSUBACK is a response control packet to acknowledge an UNSUBSCRIBE packet.
//
// The variable header of a UNSUBACK packet contains only a Packet Identifier
// taken from the UNSUBSCRIBE packet being acknowledged.
//
// The UNSUBACK packet has no payload.
//
// Defined in Section 3.11 of the specification.
type UNSUBACK struct {
	PacketID uint16
}

// Marshal converts the UNSUBACK control packet into its byte slice representation.
func (pkt *UNSUBACK) Marshal() []byte {
	return pubMarshal(pkt)
}

// unmarshal populates the UNSUBACK control packet from the VAP.
func (pkt *UNSUBACK) unmarshal(VAP []byte) error {
	return pubUnmarshal(pkt, VAP)
}

// Type will return the type of the UNSUBACK control packet.
func (pkt *UNSUBACK) Type() byte {
	return TypeUNSUBACK
}

// Flags will return the flags of the UNSUBACK control packet.
func (pkt *UNSUBACK) Flags() byte {
	return FlagsUNSUBACK
}

// PINGREQ is a control packet used for a PING request.
//
// The PINGREQ packet has no variable header.
//
// The PINGREQ packet has no payload.
//
// Defined in Section 3.12 of the specification.
type PINGREQ struct{}

// Marshal converts the PINGREQ control packet into its byte slice representation.
func (pkt *PINGREQ) Marshal() []byte {
	return pubMarshal(pkt)
}

// unmarshal populates the PINGREQ control packet from the VAP.
func (pkt *PINGREQ) unmarshal(VAP []byte) error {
	return pubUnmarshal(pkt, VAP)
}

// Type will return the type of the PINGREQ control packet.
func (pkt *PINGREQ) Type() byte {
	return TypePINGREQ
}

// Flags will return the flags of the PINGREQ control packet.
func (pkt *PINGREQ) Flags() byte {
	return FlagsPINGREQ
}

// PINGRESP is a response control packet used for a PING response.
//
// The PINGRESP packet has no variable header.
//
// The PINGRESP packet has no payload.
//
// Defined in Section 3.13 of the specification.
type PINGRESP struct{}

// Marshal converts the PINGRESP control packet into its byte slice representation.
func (pkt *PINGRESP) Marshal() []byte {
	return pubMarshal(pkt)
}

// unmarshal populates the PINGRESP control packet from the VAP.
func (pkt *PINGRESP) unmarshal(VAP []byte) error {
	return pubUnmarshal(pkt, VAP)
}

// Type will return the type of the PINGRESP control packet.
func (pkt *PINGRESP) Type() byte {
	return TypePINGRESP
}

// Flags will return the flags of the PINGRESP control packet.
func (pkt *PINGRESP) Flags() byte {
	return FlagsPINGRESP
}

// DISCONNECT is a control packet to notify of a client disconnection.
//
// The DISCONNECT packet has no variable header.
//
// The DISCONNECT packet has no payload.
//
// Defined in Section 3.14 of the specification.
type DISCONNECT struct{}

// Marshal converts the DISCONNECT control packet into its byte slice representation.
func (pkt *DISCONNECT) Marshal() []byte {
	return pubMarshal(pkt)
}

// unmarshal populates the DISCONNECT control packet from the VAP.
func (pkt *DISCONNECT) unmarshal(VAP []byte) error {
	return pubUnmarshal(pkt, VAP)
}

// Type will return the type of the DISCONNECT control packet.
func (pkt *DISCONNECT) Type() byte {
	return TypeDISCONNECT
}

// Flags will return the flags of the DISCONNECT control packet.
func (pkt *DISCONNECT) Flags() byte {
	return FlagsDISCONNECT
}

/******************************************************************************
 *                          Utility Functions                                 *
 ******************************************************************************/

// pubMarshal marshals the following control packets:
// PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK
// PINGREQ, PINGRESP, DISCONNECT
func pubMarshal(pkt ControllerPacket) []byte {
	var packetID uint16
	var encodePacketID bool
	var capacity int

	switch pkt.Type() {
	case TypePUBACK, TypePUBREC, TypePUBREL, TypePUBCOMP, TypeUNSUBACK:
		packetID = uint16(reflect.ValueOf(pkt).Elem().FieldByName("PacketID").Uint())
		encodePacketID = true
		capacity = 2
	case TypePINGREQ, TypePINGRESP, TypeDISCONNECT:
		encodePacketID = false
		capacity = 0
	}

	marshaled := make([]byte, 0, capacity)

	if encodePacketID {
		marshaled = append(marshaled, encodeUInt16(packetID)...)
	}
	marshaled = addFixedHeader(pkt, marshaled)

	return marshaled
}

// pubUnmarshal unmarshals the following control packets:
// PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK
// PINGREQ, PINGRESP, DISCONNECT
func pubUnmarshal(pkt ControllerPacket, VAP []byte) error {
	var errExpectedSize error
	var errInvalidPacketID error
	var expectedRemLen int
	var decodePacketID bool

	switch pkt.Type() {
	case TypePUBACK:
		errExpectedSize = ErrPUBACKExpectedSize
		errInvalidPacketID = ErrPUBACKInvalidPacketID
		expectedRemLen = 2
		decodePacketID = true
	case TypePUBREC:
		errExpectedSize = ErrPUBRECExpectedSize
		errInvalidPacketID = ErrPUBRECInvalidPacketID
		expectedRemLen = 2
		decodePacketID = true
	case TypePUBREL:
		errExpectedSize = ErrPUBRELExpectedSize
		errInvalidPacketID = ErrPUBRELInvalidPacketID
		expectedRemLen = 2
		decodePacketID = true
	case TypePUBCOMP:
		errExpectedSize = ErrPUBCOMPExpectedSize
		errInvalidPacketID = ErrPUBCOMPInvalidPacketID
		expectedRemLen = 2
		decodePacketID = true
	case TypeUNSUBACK:
		errExpectedSize = ErrUNSUBACKExpectedSize
		errInvalidPacketID = ErrUNSUBACKInvalidPacketID
		expectedRemLen = 2
		decodePacketID = true
	case TypePINGREQ:
		errExpectedSize = ErrPINGREQExpectedSize
		expectedRemLen = 0
		decodePacketID = false
	case TypePINGRESP:
		errExpectedSize = ErrPINGRESPExpectedSize
		expectedRemLen = 0
		decodePacketID = false
	case TypeDISCONNECT:
		errExpectedSize = ErrDISCONNECTExpectedSize
		expectedRemLen = 0
		decodePacketID = false
	}

	// Compare actual remaining length vs expected remaining length
	if len(VAP) != expectedRemLen {
		return errExpectedSize
	}

	// Packet ID
	if decodePacketID {
		// No error can happen since the expected size is checked and must be 2
		packetID, _, _ := decodeUInt16(VAP)
		if packetID == 0 {
			return errInvalidPacketID
		}
		reflect.ValueOf(pkt).Elem().FieldByName("PacketID").Set(reflect.ValueOf(packetID))
	}

	return nil
}

// encodeRemLength encodes the Remaining Length size into a byte slice
// to add to the fixed header of the control packet byte slice.
//
// Algorithm defined in Section 2.2.3 of the specification.
func encodeRemLength(X int) []byte {
	if X == 0 {
		encoded := make([]byte, 1)
		encoded[0] = 0x00
		return encoded
	}
	var encodedByte byte
	// Remaining Length is at most 4 bytes.
	// If a larger remaining length is encoded, this will be caught
	// by the receiver of the packet.
	remLength := make([]byte, 0, 4)
	for X > 0 {
		encodedByte = byte(X % 128)
		X = X / 128
		if X > 0 {
			encodedByte = encodedByte | 128
		}
		remLength = append(remLength, encodedByte)
	}
	return remLength
}

// decodeRemLength decodes the Remaining Length size from the byte slice of
// of a control packet.
// Since the encoded Remaining Length uses a variable number of bytes,
// the decoded length and the number of bytes used by the encoding are returned.
//
// Algorithm defined in Section 2.2.3 of the specification.
func decodeRemLength(pkt []byte) (length int, used int, e error) {
	var encodedByte byte
	// Starting byte of Remaining Length starts on the 2nd byte
	// (i.e. index 1 in the slice)
	currentByte := 1
	encodedByte = pkt[currentByte]
	used = 1
	multiplier := 1
	length = int(encodedByte&127) * multiplier
	for (encodedByte & 128) != 0 {
		multiplier *= 128

		currentByte++
		used++

		encodedByte = pkt[currentByte]

		length += int(encodedByte&127) * multiplier

		if multiplier > 128*128*128 {
			return 0, 0, ErrRemLengthTooLarge
		}
	}
	return length, used, nil
}

// encodeUInt16 will encode a uint16 into a slice of bytes of length 2 with
// the MSB first followed by the LSB.
func encodeUInt16(i uint16) []byte {
	encoded := make([]byte, 2)
	encoded[0] = byte(i >> 8)
	encoded[1] = byte(i & 0xff)
	return encoded
}

// encodeString will encode a string into a slice of bytes where the first
// two bytes are the String Length MSB and String Length LSB, followed by
// each character converted to a byte.
//
// Defined in Section 1.5.3 of the specification.
func encodeString(s string) []byte {
	length := len(s)
	if length > 0 {
		encoded := make([]byte, 2+length)
		copy(encoded, encodeUInt16(uint16(length)))
		for i, r := range s {
			encoded[i+2] = byte(r)
		}
		return encoded
	}
	return nil
}

// decodeUInt16 will decode an int from a byte slice.
// Byte slice must have at least length 2 with the MSB followed by the LSB.
// Returns the decoded int, the rest of the byte slice, and any error
// which may have occurred.
func decodeUInt16(b []byte) (uint16, []byte, error) {
	if len(b) < 2 {
		return 0, nil, ErrDecodeUInt16
	}
	var decoded uint16 = uint16(b[0])
	decoded <<= 8
	decoded |= uint16(b[1])
	return decoded, b[2:], nil
}

// decodeString will decode a string from a byte slice where the first two bytes
// are the String Length MSB and String Length LSB, followed by each character.
// Returns the decoded string, the rest of the byte slice, and any error
// which may have occurred.
// If the string is required and no string can be decoded, an error will be returned.
// Otherwise, no error is returned.
//
// Defined in Section 1.5.3 of the specification.
func decodeString(b []byte, required bool) (string, []byte, error) {
	length, bytes, err := decodeUInt16(b)
	// Required string should return error
	if err != nil && required {
		return "", nil, ErrRequiredString
	}
	// Optional string returns no error
	if err != nil && !required {
		return "", b, nil
	}
	if len(bytes) < int(length) {
		return "", nil, ErrDecodeString
	}
	decoded := string(bytes[:length])
	return decoded, bytes[length:], nil
}

// IsValidTopicName determines if the string given is a valid Topic Name.
//
// Defined in Section 4.7 of the specification.
func IsValidTopicName(s string) bool {
	// The wildcard characters can be used in Topic Filters, but MUST NOT be used
	// within a Topic Name [MQTT-4.7.1-1].
	// All Topic Names and Topic Filters MUST be at least one character long [MQTT-4.7.3-1]
	if len(s) == 0 {
		return false
	}

	for _, c := range s {
		if c == '#' || c == '+' {
			return false
		}
	}
	return true
}

// IsValidTopicFilter determines if the string given is a valid Topic Filter.
//
// Defined in Section 4.7 of the specification.
func IsValidTopicFilter(s string) bool {
	// All Topic Names and Topic Filters MUST be at least one character long [MQTT-4.7.3-1]
	//
	// The number sign (‘#’ U+0023) is a wildcard character that matches any
	// number of levels within a topic.
	// The multi-level wildcard character MUST be specified either on its own or
	// following a topic level separator. In either case it MUST be the last
	// character specified in the Topic Filter [MQTT-4.7.1-2].
	//
	// The plus sign (‘+’ U+002B) is a wildcard character that matches
	// only one topic level.
	// The single-level wildcard can be used at any level in the Topic Filter,
	// including first and last levels. Where it is used it MUST occupy an entire
	// level of the filter [MQTT-4.7.1-3].
	if len(s) == 0 {
		return false
	}

	for i := range s {
		if s[i] == '#' {
			// Valid case: i == len(s) - 1 && (i == 0 || s[i-1] == `/`)
			if i != len(s)-1 || (i != 0 && s[i-1] != '/') {
				return false
			}
		} else if s[i] == '+' {
			// Valid cases:
			// Single character: len(s) == 1
			// First character: i == 0 && s[i+1] == `/`
			// Last character: i == len(s) - 1 && s[i-1] == `/`
			// Middle: s[i-1] == `/` && s[i+1] == `/`
			if len(s) != 1 {
				if (i == 0 && s[i+1] != '/') || (i == len(s)-1 && s[i-1] != '/') || (s[i-1] != '/' || s[i+1] != '/') {
					return false
				}
			}
		}
	}

	return true
}

// concatErrors concatenates all of the errors into a single one.
func concatErrors(errs ...error) error {
	errStrings := make([]string, len(errs))
	for i, err := range errs {
		errStrings[i] = err.Error()
	}
	return errors.New(strings.Join(errStrings, ": "))
}

// createError returns an error which happened during
// the creation of a control packet.
func createError(pktName, err string) error {
	return errors.New("Failed to create " + pktName + " packet: " + err)
}

// marshalError returns an error which happened during
// the marshalling of a control packet.
func marshalError(pktName, err string) error {
	return errors.New("Failed to marshal " + pktName + " packet: " + err)
}

// unmarshalError returns an error which happened during
// the unmarshalling of a control packet.
func unmarshalError(pktName, err string) error {
	return errors.New("Failed to unmarshal " + pktName + " packet: " + err)
}
