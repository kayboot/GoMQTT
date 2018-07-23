package gomqtt

// ControlPkt is the main form of communication between
// an MQTT server and client.
type ControlPkt interface {
    // Marshall transforms the struct representation into bytes
    // to be sent over the wire.
    Marshall() ([]byte, err)
}

// FixedHeader is the fixed header part of each control packet.
//
// Each control packet has a unique type, specific flags, and the remaining
// length of the packet (not including the fixed header).
//
// Defined in Section 2.2 of the specification.
type FixedHeader struct {
  Type int
  Flags int
  Length int
}

// CONNECT is a control packet used by clients to request a
// connection to a server.
//
// Along with the fixed header, the CONNECT packet also contains the following
// as part of its variable header:
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
// respectively.
//
// Defined in Section 3.1 of the specification.
type CONNECT struct {
  FixedHeader
  Name string
  Level int
  Reserved bool
  CleanSession bool
  WillFlag bool
  WillQoS bool
  WillRetain bool
  PasswordFlag bool
  UsernameFlag bool
  ClientID string
  WillTopic string
  WillMessage string
  Username string
  Password string
}

// CONNACK is a control packet to acknowledge connection requests.
//
// There is currently only a single flag being used, the Session Present Flag.
// This tells a client if a session already existed on this server.
//
// The other piece of data in the packet is the connection return code.
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
  FixedHeader
  SessionPresent bool
  ReturnCode int
}

// Unmarshall transforms bytes received from a connection into a control packet.
func Unmarshall(b []byte) (pkt ControlPkt, err error) {
  return nil, "NOT IMPLEMENTED"
}
