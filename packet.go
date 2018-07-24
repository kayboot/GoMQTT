package gomqtt

// ControlPkt is the main form of communication between
// an MQTT server and client.
type ControlPkt interface {
    // Marshall transforms the struct representation into bytes
    // to be sent over the wire.
    Marshall() ([]byte, error)

    // Unmarshall transforms the bytes received over the wire into
    // the struct representation of the packet.
    Unmarshall([]byte) (error)
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
  FixedHeader
  Name string
  Level int
  CFlags CONNECTFlags
  ClientID string
  WillTopic string
  WillMessage string
  Username string
  Password string
}

// CONNECTFlags represents the connect flags in the variable header of the
// CONNECT control packet.
//
// Defined in Section 3.1.2.3 of the specification.
type CONNECTFlags struct {
  CleanSession bool
  WillFlag bool
  WillQoS int
  WillRetain bool
  PasswordFlag bool
  UserNameFlag bool
}

// CONNACK is a response control packet to acknowledge connection requests.
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

// PUBLISH is a control packet to publish messages.
//
// The flags in the fixed header are:
//  - DUP: whether this is a duplicate of a message that
//    the sending party has already sent.
//  - QoS level: level of assurance for delivery of the application message.
//  - RETAIN: whether the application message in this packet should be retained
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
  FixedHeader
  DUP bool
  QoS int
  RETAIN bool
  TopicName string
  PktID uint16
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
  FixedHeader
  PktID uint16
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
  FixedHeader
  PktID uint16
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
  FixedHeader
  PktID uint16
}

// PUBCOMP is a response control packet to a PUBREL packet.
// This is the 4th and final packet of the QoS 2 protocol exchange.
//
// The variable header of the PUBCOMP packet contains only a Packet Identifier
// taken from the PUBCOMP packet being acknowledged.
//
// The PUBCOMP packet has no payload.
//
// Defined in Section 3.7 of the specification.
type PUBCOMP struct {
  FixedHeader
  PktID uint16
}

// TopicQosPair is a pair of Topic Filter and QoS level contained in the payload
// of a SUBSCRIBE control packet.
//
// Defined in Section 3.8.3 of the specification.
type TopicQoSPair struct {
  TopicFilter string
  QoS int
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
  FixedHeader
  PktID uint16
  TQPairs []TopicQoSPair
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
    FixedHeader
    PktID uint16
    ReturnCodes []int
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
  FixedHeader
  PktID uint16
  TopicFilters []string
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
  FixedHeader
  PktID uint16
}

// PINGREQ is a control packet used for a PING request.
//
// The PINGREQ packet has no variable header.
//
// The PINGREQ packet has no payload.
//
// Defined in Section 3.12 of the specification.
type PINGREQ struct {
  FixedHeader
}

// PINGRESP is a response control packet used for a PING response.
//
// The PINGRESP packet has no variable header.
//
// The PINGRESP packet has no payload.
//
// Defined in Section 3.13 of the specification.
type PINGRESP struct {
  FixedHeader
}

// DISCONNECT is a control packet to notify of a client disconnection.
//
// The DISCONNECT packet has no variable header.
//
// The DISCONNECT packet has no payload.
//
// Defined in Section 3.14 of the specification.
type DISCONNECT struct {
  FixedHeader
}

// Unmarshall is a general function which transforms bytes into a ControlPkt
// according to the MQTT Control Packet type extracted from the first byte.
func Unmarshall(b []byte) (ControlPkt, error) {
  return nil, "NOT IMPLEMENTED"
}
