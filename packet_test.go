package gomqtt_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	. "github.com/kayboot/gomqtt"
)

/*******************************************************
*                  Helper Functions                    *
********************************************************/

type ByteSlice []byte

func (b ByteSlice) String() string {
	var output string = "["
	for i := range b {
		output += fmt.Sprintf("0x%02x", b[i])
		if i != len(b)-1 {
			output += " "
		}
	}
	output += "]"
	return output
}

func pack(r []byte) (num uint16) {
	num = uint16(r[0])
	num <<= 8
	num |= uint16(r[1])
	return
}

func unpack(num uint16) (r []byte) {
	r = make([]byte, 2)
	r[0] = byte(num >> 8)
	r[1] = byte(num & 0xff)
	return
}

func randBytes(num int, size uint) [][]byte {
	rands := make([][]byte, num)
	for i := range rands {
		rands[i] = make([]byte, size)
		rand.Read(rands[i])
	}
	return rands
}

type marshalTest struct {
	pkt      ControllerPacket
	expected []byte
}

func testMarshal(t *testing.T, tests []marshalTest) {
	var marshaled []byte
	for _, test := range tests {
		marshaled = test.pkt.Marshal()
		if !bytes.Equal(marshaled, test.expected) {
			t.Errorf("Packet %+v marshaled to %v, want %v", test.pkt, ByteSlice(marshaled), ByteSlice(test.expected))
		}
	}
}

type errUnmarshalTest struct {
	encoded  []byte
	expected error
}

func testErrUnmarshal(t *testing.T, tests []errUnmarshalTest) {
	for _, test := range tests {
		_, err := Unmarshal(test.encoded)
		if err == nil {
			t.Errorf("Unmarshal %v did not fail, want error '%v'", ByteSlice(test.encoded), test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with '%v', want '%v'", ByteSlice(test.encoded), err, test.expected)
		}
	}
}

type unmarshalTest struct {
	encoded  []byte
	expected ControllerPacket
}

func testUnmarshal(t *testing.T, tests []unmarshalTest) {
	for _, test := range tests {
		cpkt, err := Unmarshal(test.encoded)
		if err != nil {
			t.Errorf("Unmarshal %v errored '%v', want %+v", ByteSlice(test.encoded), err, test.expected)
		} else if cpkt.Type() != test.expected.Type() {
			t.Errorf("Unmarshal %v gave type %v, want %v", ByteSlice(test.encoded), cpkt.Type(), test.expected.Type())
		} else if !reflect.DeepEqual(cpkt, test.expected) {
			t.Errorf("Unmarshal %v gave %+v, want %+v", ByteSlice(test.encoded), cpkt, test.expected)
		}
	}
}

func testMarshalPacket(t *testing.T, pktType byte, fixedHeader []byte) {
	var numTests int = 10

	tests := make([]marshalTest, numTests)
	for i := range tests {
		tests[i] = marshalTest{
			expected: make([]byte, 0, 4),
		}
		tests[i].expected = append(tests[i].expected, fixedHeader...)
	}

	rands := randBytes(numTests, uint(2))

	switch pktType {
	case TypePUBACK:
		for i, random := range rands {
			tests[i].pkt = &PUBACK{pack(random)}
			tests[i].expected = append(tests[i].expected, random...)
		}
	case TypePUBREC:
		for i, random := range rands {
			tests[i].pkt = &PUBREC{pack(random)}
			tests[i].expected = append(tests[i].expected, random...)
		}
	case TypePUBREL:
		for i, random := range rands {
			tests[i].pkt = &PUBREL{pack(random)}
			tests[i].expected = append(tests[i].expected, random...)
		}
	case TypePUBCOMP:
		for i, random := range rands {
			tests[i].pkt = &PUBCOMP{pack(random)}
			tests[i].expected = append(tests[i].expected, random...)
		}
	case TypeUNSUBACK:
		for i, random := range rands {
			tests[i].pkt = &UNSUBACK{pack(random)}
			tests[i].expected = append(tests[i].expected, random...)
		}
	case TypePINGREQ:
		for i := range rands {
			tests[i].pkt = &PINGREQ{}
		}
	case TypePINGRESP:
		for i := range rands {
			tests[i].pkt = &PINGRESP{}
		}
	case TypeDISCONNECT:
		for i := range rands {
			tests[i].pkt = &DISCONNECT{}
		}
	}

	testMarshal(t, tests)
}

func testUnmarshalPacket(t *testing.T, pktType byte, fixedHeader []byte) {
	var numTests int = 10

	tests := make([]unmarshalTest, numTests)
	for i := range tests {
		tests[i] = unmarshalTest{
			encoded: make([]byte, 0, 4),
		}
		tests[i].encoded = append(tests[i].encoded, fixedHeader...)
	}

	rands := randBytes(numTests, uint(2))

	switch pktType {
	case TypePUBACK:
		for i, random := range rands {
			tests[i].expected = &PUBACK{pack(random)}
			tests[i].encoded = append(tests[i].encoded, random...)
		}
	case TypePUBREC:
		for i, random := range rands {
			tests[i].expected = &PUBREC{pack(random)}
			tests[i].encoded = append(tests[i].encoded, random...)
		}
	case TypePUBREL:
		for i, random := range rands {
			tests[i].expected = &PUBREL{pack(random)}
			tests[i].encoded = append(tests[i].encoded, random...)
		}
	case TypePUBCOMP:
		for i, random := range rands {
			tests[i].expected = &PUBCOMP{pack(random)}
			tests[i].encoded = append(tests[i].encoded, random...)
		}
	case TypeUNSUBACK:
		for i, random := range rands {
			tests[i].expected = &UNSUBACK{pack(random)}
			tests[i].encoded = append(tests[i].encoded, random...)
		}
	case TypePINGREQ:
		for i := range rands {
			tests[i].expected = &PINGREQ{}
		}
	case TypePINGRESP:
		for i := range rands {
			tests[i].expected = &PINGRESP{}
		}
	case TypeDISCONNECT:
		for i := range rands {
			tests[i].expected = &DISCONNECT{}
		}
	}

	testUnmarshal(t, tests)
}

/*******************************************************
*                      CONNACK                         *
********************************************************/

func TestMarshalCONNACK(t *testing.T) {
	tests := []marshalTest{
		{&CONNACK{false, 0}, []byte{0x20, 0x02, 0x00, 0x00}},
		{&CONNACK{false, 4}, []byte{0x20, 0x02, 0x00, 0x04}},
		{&CONNACK{false, 0x2e}, []byte{0x20, 0x02, 0x00, 0x2e}},
		{&CONNACK{true, 5}, []byte{0x20, 0x02, 0x01, 0x05}},
		{&CONNACK{true, 6}, []byte{0x20, 0x02, 0x01, 0x06}},
		{&CONNACK{true, 0xf3}, []byte{0x20, 0x02, 0x01, 0xf3}},
	}

	testMarshal(t, tests)
}

func TestErrUnmarshalCONNACK(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0x27, 0x02, 0x01, 0x00}, ErrCONNACKFlags},        // Invalid Packet Flags
		{[]byte{0x20, 0x40, 0x00, 0x04}, ErrLengthMismatch},      // Remaining Length mismatch
		{[]byte{0x20, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrCONNACK}, // Extra data
		{[]byte{0x20, 0x02, 0x51, 0x03}, ErrCAckFlags},           // Invalid Connect Acknowledge flags
		{[]byte{0x20, 0x02, 0x01, 0x43}, ErrCONNACKReturnCode},   // Invalid Return code
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalCONNACK(t *testing.T) {
	tests := []unmarshalTest{
		{[]byte{0x20, 0x02, 0x00, 0x04}, &CONNACK{false, 4}},
		{[]byte{0x20, 0x02, 0x01, 0x05}, &CONNACK{true, 5}},
		{[]byte{0x20, 0x02, 0x00, 0x00}, &CONNACK{false, 0}},
		{[]byte{0x20, 0x02, 0x01, 0x02}, &CONNACK{true, 2}},
	}

	testUnmarshal(t, tests)
}

/*******************************************************
*                      PUBLISH                         *
********************************************************/

func TestMarshalPUBLISHFlags(t *testing.T) {
	tests := []marshalTest{
		{
			&PUBLISH{false, 0, false, "a/b", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x30, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x13, 0x36, 0x33, 0xf2},
		},
		{
			&PUBLISH{false, 0, true, "a/b", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x31, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x13, 0x36, 0x33, 0xf2},
		},
		{
			&PUBLISH{true, 0, false, "a/b", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x38, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x13, 0x36, 0x33, 0xf2},
		},
		{
			&PUBLISH{true, 0, true, "a/b", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x39, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x13, 0x36, 0x33, 0xf2},
		},
		{
			&PUBLISH{true, 1, false, "a/b", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x3a, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x13, 0x36, 0x33, 0xf2},
		},
		{
			&PUBLISH{true, 2, true, "a/b", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x3d, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x13, 0x36, 0x33, 0xf2},
		},
		{
			&PUBLISH{false, 3, true, "a/b", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x37, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x13, 0x36, 0x33, 0xf2},
		},
	}

	testMarshal(t, tests)
}

func TestMarshalPUBLISHTopicName(t *testing.T) {
	tests := []marshalTest{
		{
			&PUBLISH{false, 0, false, "hello/world", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x30, 0x11, 0x00, 0x0b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2f,
				0x77, 0x6f, 0x72, 0x6c, 0x64, 0x13, 0x36, 0x33, 0xf2},
		},
		{
			&PUBLISH{false, 0, false, "abiglongsentencewrittenhere", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x30, 0x21, 0x00, 0x1b, 0x61, 0x62, 0x69, 0x67, 0x6c, 0x6f, 0x6e,
				0x67, 0x73, 0x65, 0x6e, 0x74, 0x65, 0x6e, 0x63, 0x65, 0x77, 0x72, 0x69,
				0x74, 0x74, 0x65, 0x6e, 0x68, 0x65, 0x72, 0x65, 0x13, 0x36, 0x33, 0xf2},
		},
		{
			&PUBLISH{false, 0, false, "+/+/#", 0x1336, []byte{0x33, 0xf2}},
			[]byte{0x30, 0x0b, 0x00, 0x5, 0x2b, 0x2f, 0x2b, 0x2f, 0x23, 0x13, 0x36,
				0x33, 0xf2},
		},
	}

	testMarshal(t, tests)
}

func TestMarshalPUBLISHPacketID(t *testing.T) {
	tests := []marshalTest{
		{
			&PUBLISH{false, 3, true, "a/b", 0xfa34, []byte{0x33, 0xf2}},
			[]byte{0x37, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0xfa, 0x34, 0x33, 0xf2},
		},
		{
			&PUBLISH{false, 3, true, "a/b", 0x1946, []byte{0x33, 0xf2}},
			[]byte{0x37, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x19, 0x46, 0x33, 0xf2},
		},
		{
			&PUBLISH{false, 3, true, "a/b", 0x0000, []byte{0x33, 0xf2}},
			[]byte{0x37, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x00, 0x00, 0x33, 0xf2},
		},
	}

	testMarshal(t, tests)
}

func TestMarshalPUBLISHMessage(t *testing.T) {
	numTests := 10

	tests := make([]marshalTest, numTests)
	tests[0] = marshalTest{
		&PUBLISH{false, 3, true, "a/b", 0xfa34, []byte{}},
		[]byte{0x37, 0x07, 0x00, 0x03, 0x61, 0x2f, 0x62, 0xfa, 0x34},
	}

	for i := range tests {
		if i == 0 {
			continue
		}
		randomSize := make([]byte, 2)
		rand.Read(randomSize)
		randomMessage := make([]byte, pack(randomSize))
		rand.Read(randomMessage)
		tests[i].pkt = &PUBLISH{false, 3, true, "a/b", 0xfa34, randomMessage}
		remLen := EncodeRemLength(7 + len(randomMessage))
		expected := make([]byte, 0, 1+len(remLen)+7+len(randomMessage))
		expected = append(expected, 0x37)
		expected = append(expected, remLen...)
		expected = append(expected, []byte{0x00, 0x03, 0x61, 0x2f, 0x62, 0xfa, 0x34}...)
		expected = append(expected, randomMessage...)
		tests[i].expected = expected
	}

	testMarshal(t, tests)
}

func TestErrUnmarshalPUBLISH(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0x36, 0x02, 0x13, 0x20}, ErrPUBLISHInvalidQoS}, // Invalid Packet Flags (i.e. QoS value)
		{[]byte{0x30, 0x41, 0x00, 0x04}, ErrLengthMismatch},    // Remaining Length mismatch
		{[]byte{0x30, 0x00}, ErrMissingTopicName},              // Missing Topic Name
		{[]byte{0x30, 0x02, 0x00, 0x01}, ErrMissingTopicName},
		{[]byte{0x30, 0x04, 0x01, 0x02, 0x4e, 0x5f}, ErrMissingTopicName},
		{[]byte{0x30, 0x07, 0x00, 0x05, 0x61, 0x2f, 0x23, 0x2f, 0x62}, ErrTopicName},             // Invalid Topic Name a/#/b
		{[]byte{0x30, 0x07, 0x00, 0x05, 0x2f, 0x2b, 0x2b, 0x2f, 0x61}, ErrTopicName},             // /++/a
		{[]byte{0x30, 0x09, 0x00, 0x05, 0x2f, 0x2b, 0x2b, 0x2f, 0x61, 0x32, 0x45}, ErrTopicName}, // /++/a with Packet ID
		{[]byte{0x32, 0x05, 0x00, 0x03, 0x33, 0x37, 0x36}, ErrPUBLISHPacketID},                   // Missing Packet ID
		{[]byte{0x34, 0x06, 0x00, 0x03, 0x33, 0x37, 0x36, 0x02}, ErrPUBLISHPacketID},
		{[]byte{0x32, 0x07, 0x00, 0x03, 0x33, 0x37, 0x36, 0x00, 0x00}, ErrPUBLISHInvalidPacketID}, // Invalid Packet ID
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalPUBLISHFlags(t *testing.T) {
	tests := []unmarshalTest{
		{
			// DUP: true, QoS: 0, RETAIN: true
			[]byte{0x39, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x76, 0x88, 0x32, 0x44},
			&PUBLISH{true, 0, true, "a/b", 0x00, []byte{0x76, 0x88, 0x32, 0x44}},
		},
		{
			// DUP:false, QoS: 1, RETAIN: true
			[]byte{0x33, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x01, 0xf4, 0x32, 0x44},
			&PUBLISH{false, 1, true, "a/b", 0x01f4, []byte{0x32, 0x44}},
		},
		{
			// DUP: true, QoS: 1, RETAIN: false
			[]byte{0x3a, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x90, 0x0c, 0x32, 0x44},
			&PUBLISH{true, 1, false, "a/b", 0x900c, []byte{0x32, 0x44}},
		},
		{
			// DUP: true, QoS: 2, RETAIN: false
			[]byte{0x3c, 0x09, 0x00, 0x03, 0x61, 0x2f, 0x62, 0x00, 0x01, 0x32, 0x44},
			&PUBLISH{true, 2, false, "a/b", 0x0001, []byte{0x32, 0x44}},
		},
	}

	testUnmarshal(t, tests)
}

func TestUnmarshalPUBLISHTopicName(t *testing.T) {
	topicNames := []string{
		"first/second/third",
		"one",
		"a/b/c/d/e/f/g/h/i/j/",
		"somealdewjfweflweklfweoifwelkfwnjfjkwnefw",
		"level1/level2/level3",
		"/",
	}

	tests := make([]unmarshalTest, len(topicNames))

	for i, topicName := range topicNames {
		message := []byte{0x21, 0x44, 0xfe}
		tests[i].expected = &PUBLISH{true, 1, false, topicName, 0x5428, message}
		capacity := 2 + 2 + len(topicName) + 2 + len(message)
		tests[i].encoded = make([]byte, 0, capacity)
		tests[i].encoded = append(tests[i].encoded, byte(0x3a))
		tests[i].encoded = append(tests[i].encoded, byte(capacity-2))
		tests[i].encoded = append(tests[i].encoded, unpack(uint16(len(topicName)))...)
		tests[i].encoded = append(tests[i].encoded, []byte(topicName)...)
		tests[i].encoded = append(tests[i].encoded, []byte{0x54, 0x28}...)
		tests[i].encoded = append(tests[i].encoded, message...)
	}

	testUnmarshal(t, tests)
}

func TestUnmarshalPUBLISHPacketID(t *testing.T) {
	numTests := 10

	tests := make([]unmarshalTest, numTests)
	tests[0] = unmarshalTest{
		[]byte{0x30, 0x07, 0x00, 0x03, 0x54, 0x55, 0x2f, 0x18, 0x99},
		&PUBLISH{false, 0, false, "TU/", 0x00, []byte{0x18, 0x99}},
	}

	packetIDs := randBytes(numTests, uint(2))

	for i := range tests {
		if i == 0 {
			continue
		}
		message := []byte{0x21, 0x44, 0xfe}
		pktID := pack(packetIDs[i])
		tests[i].expected = &PUBLISH{true, 1, false, "a/b", pktID, message}
		capacity := 2 + 2 + 3 + 2 + len(message)
		tests[i].encoded = make([]byte, 0, capacity)
		tests[i].encoded = append(tests[i].encoded, byte(0x3a))
		tests[i].encoded = append(tests[i].encoded, byte(capacity-2))
		tests[i].encoded = append(tests[i].encoded, unpack(uint16(3))...)
		tests[i].encoded = append(tests[i].encoded, []byte("a/b")...)
		tests[i].encoded = append(tests[i].encoded, packetIDs[i]...)
		tests[i].encoded = append(tests[i].encoded, message...)
	}

	testUnmarshal(t, tests)
}

func TestUnmarshalPUBLISHMessage(t *testing.T) {
	numTests := 10

	tests := make([]unmarshalTest, numTests)
	tests[0] = unmarshalTest{
		[]byte{0x34, 0x07, 0x00, 0x03, 0x54, 0x55, 0x2f, 0x18, 0x99},
		&PUBLISH{false, 2, false, "TU/", 0x1899, []byte{}},
	}

	messageLengths := randBytes(numTests, uint(2))

	for i := range tests {
		if i == 0 {
			continue
		}
		//t.Logf("Message Length: %d\n", pack(messageLengths[i]))
		message := randBytes(1, uint(pack(messageLengths[i])))[0]
		//t.Logf("Match: %v\n", uint(len(message)) == uint(pack(messageLengths[i])))
		//t.Logf("Remaining Length: 0x%02x\n", 2+3+2+len(message))
		remLen := EncodeRemLength(2 + 3 + 2 + len(message))
		tests[i].expected = &PUBLISH{true, 1, false, "a/b", 0x5463, message}
		capacity := 2 + len(remLen) + 3 + 2 + len(message)
		tests[i].encoded = make([]byte, 0, capacity)
		tests[i].encoded = append(tests[i].encoded, byte(0x3a))
		tests[i].encoded = append(tests[i].encoded, remLen...)
		tests[i].encoded = append(tests[i].encoded, unpack(uint16(3))...)
		tests[i].encoded = append(tests[i].encoded, []byte("a/b")...)
		tests[i].encoded = append(tests[i].encoded, []byte{0x54, 0x63}...)
		tests[i].encoded = append(tests[i].encoded, message...)
	}

	testUnmarshal(t, tests)
}

/*******************************************************
*                       PUBACK                         *
********************************************************/

func TestMarshalPUBACK(t *testing.T) {
	testMarshalPacket(t, TypePUBACK, []byte{0x40, 0x02})
}

func TestErrUnmarshalPUBACK(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0x4c, 0x02, 0x13, 0x20}, ErrPUBACKFlags},                    // Invalid Packet Flags
		{[]byte{0x40, 0x31, 0x00, 0x04}, ErrLengthMismatch},                 // Remaining Length mismatch
		{[]byte{0x40, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrPUBACKExpectedSize}, // Extra data
		{[]byte{0x40, 0x02, 0x00, 0x00}, ErrPUBACKInvalidPacketID},          // Invalid Packet ID
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalPUBACK(t *testing.T) {
	testUnmarshalPacket(t, TypePUBACK, []byte{0x40, 0x02})
}

/*******************************************************
*                       PUBREC                         *
********************************************************/

func TestMarshalPUBREC(t *testing.T) {
	testMarshalPacket(t, TypePUBREC, []byte{0x50, 0x02})
}

func TestErrUnmarshalPUBREC(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0x5c, 0x02, 0x13, 0x20}, ErrPUBRECFlags},                    // Invalid Packet Flags
		{[]byte{0x50, 0x3c, 0x00, 0x04}, ErrLengthMismatch},                 // Remaining Length mismatch
		{[]byte{0x50, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrPUBRECExpectedSize}, // Extra data
		{[]byte{0x50, 0x02, 0x00, 0x00}, ErrPUBRECInvalidPacketID},          // Invalid Packet ID
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalPUBREC(t *testing.T) {
	testUnmarshalPacket(t, TypePUBREC, []byte{0x50, 0x02})
}

/*******************************************************
*                       PUBREL                         *
********************************************************/

func TestMarshalPUBREL(t *testing.T) {
	testMarshalPacket(t, TypePUBREL, []byte{0x62, 0x02})
}

func TestErrUnmarshalPUBREL(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0x63, 0x02, 0x13, 0x20}, ErrPUBRELFlags},                    // Invalid Packet Flags
		{[]byte{0x62, 0x63, 0x00, 0x04}, ErrLengthMismatch},                 // Remaining Length mismatch
		{[]byte{0x62, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrPUBRELExpectedSize}, // Extra data
		{[]byte{0x62, 0x02, 0x00, 0x00}, ErrPUBRELInvalidPacketID},          // Invalid Packet ID
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalPUBREL(t *testing.T) {
	testUnmarshalPacket(t, TypePUBREL, []byte{0x62, 0x02})
}

/*******************************************************
*                       PUBCOMP                        *
********************************************************/

func TestMarshalPUBCOMP(t *testing.T) {
	testMarshalPacket(t, TypePUBCOMP, []byte{0x70, 0x02})
}

func TestErrUnmarshalPUBCOMP(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0x7e, 0x02, 0x13, 0x20}, ErrPUBCOMPFlags},                    // Invalid Packet Flags
		{[]byte{0x70, 0x63, 0x00, 0x04}, ErrLengthMismatch},                  // Remaining Length mismatch
		{[]byte{0x70, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrPUBCOMPExpectedSize}, // Extra data
		{[]byte{0x70, 0x02, 0x00, 0x00}, ErrPUBCOMPInvalidPacketID},          // Invalid Packet ID
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalPUBCOMP(t *testing.T) {
	testUnmarshalPacket(t, TypePUBCOMP, []byte{0x70, 0x02})
}

/*******************************************************
*                       UNSUBACK                       *
********************************************************/

func TestMarshalUNSUBACK(t *testing.T) {
	testMarshalPacket(t, TypeUNSUBACK, []byte{0xb0, 0x02})
}

func TestErrUnmarshalUNSUBACK(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0xb5, 0x02, 0x13, 0x20}, ErrUNSUBACKFlags},                    // Invalid Packet Flags
		{[]byte{0xb0, 0x42, 0x00, 0x04}, ErrLengthMismatch},                   // Remaining Length mismatch
		{[]byte{0xb0, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrUNSUBACKExpectedSize}, // Extra data
		{[]byte{0xb0, 0x02, 0x00, 0x00}, ErrUNSUBACKInvalidPacketID},          // Invalid Packet ID
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalUNSUBACK(t *testing.T) {
	testUnmarshalPacket(t, TypeUNSUBACK, []byte{0xb0, 0x02})
}

/*******************************************************
*                        PINGREQ                       *
********************************************************/

func TestMarshalPINGREQ(t *testing.T) {
	testMarshalPacket(t, TypePINGREQ, []byte{0xc0, 0x00})
}

func TestErrUnmarshalPINGREQ(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0xce, 0x00}, ErrPINGREQFlags},                    // Invalid Packet Flags
		{[]byte{0xc0, 0x1e, 0x00, 0x04}, ErrLengthMismatch},      // Remaining Length mismatch
		{[]byte{0xc0, 0x02, 0x00, 0x05}, ErrPINGREQExpectedSize}, // Extra data
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalPINGREQ(t *testing.T) {
	testUnmarshalPacket(t, TypePINGREQ, []byte{0xc0, 0x00})
}

/*******************************************************
*                       PINGRESP                       *
********************************************************/

func TestMarshalPINGRESP(t *testing.T) {
	testMarshalPacket(t, TypePINGRESP, []byte{0xd0, 0x00})
}

func TestErrUnmarshalPINGRESP(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0xd2, 0x00}, ErrPINGRESPFlags},                    // Invalid Packet Flags
		{[]byte{0xd0, 0x1e, 0x00, 0x04}, ErrLengthMismatch},       // Remaining Length mismatch
		{[]byte{0xd0, 0x02, 0x00, 0x05}, ErrPINGRESPExpectedSize}, // Extra data
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalPINGRESP(t *testing.T) {
	testUnmarshalPacket(t, TypePINGRESP, []byte{0xd0, 0x00})
}

/*******************************************************
*                      DISCONNECT                      *
********************************************************/

func TestMarshalDISCONNECT(t *testing.T) {
	testMarshalPacket(t, TypeDISCONNECT, []byte{0xe0, 0x00})
}

func TestErrUnmarshalDISCONNECT(t *testing.T) {
	tests := []errUnmarshalTest{
		{[]byte{0xe8, 0x00}, ErrDISCONNECTFlags},                    // Invalid Packet Flags
		{[]byte{0xe0, 0x77, 0x00, 0x04}, ErrLengthMismatch},         // Remaining Length mismatch
		{[]byte{0xe0, 0x02, 0x00, 0x05}, ErrDISCONNECTExpectedSize}, // Extra data
	}

	testErrUnmarshal(t, tests)
}

func TestUnmarshalDISCONNECT(t *testing.T) {
	testUnmarshalPacket(t, TypeDISCONNECT, []byte{0xe0, 0x00})
}
