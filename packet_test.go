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

func pack(r []byte) (packetID uint16) {
	packetID = uint16(r[0])
	packetID <<= 8
	packetID |= uint16(r[1])
	return
}

func randBytes(num int) [][]byte {
	rands := make([][]byte, num)
	for i := range rands {
		rands[i] = make([]byte, 2)
		rand.Read(rands[i])
	}
	return rands
}

func testMarshalPacket(t *testing.T, pktType byte, fixedHeader []byte) {
	type testStruct struct {
		pkt      ControllerPacket
		expected []byte
	}

	var numTests int = 10

	tests := make([]testStruct, numTests)
	for i := range tests {
		tests[i] = testStruct{
			expected: make([]byte, 0, 4),
		}
		tests[i].expected = append(tests[i].expected, fixedHeader...)
	}

	rands := randBytes(numTests)

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
	}

	var marshaled []byte
	for _, test := range tests {
		marshaled = test.pkt.Marshal()
		if !bytes.Equal(marshaled, test.expected) {
			t.Errorf("Packet %+v marshaled to %v, want %v", test.pkt, ByteSlice(marshaled), ByteSlice(test.expected))
		}
	}
}

func testUnmarshalPacket(t *testing.T, pktType byte, fixedHeader []byte) {
	type testStruct struct {
		encoded  []byte
		expected ControllerPacket
	}

	var numTests int = 10

	tests := make([]testStruct, numTests)
	for i := range tests {
		tests[i] = testStruct{
			encoded: make([]byte, 0, 4),
		}
		tests[i].encoded = append(tests[i].encoded, fixedHeader...)
	}

	rands := randBytes(numTests)

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
	}

	for _, test := range tests {
		cpkt, err := Unmarshal(test.encoded)
		if err != nil {
			t.Errorf("Unmarshal %v errored '%v', want %+v", ByteSlice(test.encoded), err, test.expected)
		} else {
			var pkt ControllerPacket
			var ok bool
			switch pktType {
			case TypePUBACK:
				pkt, ok = cpkt.(*PUBACK)
			case TypePUBREC:
				pkt, ok = cpkt.(*PUBREC)
			case TypePUBREL:
				pkt, ok = cpkt.(*PUBREL)
			case TypePUBCOMP:
				pkt, ok = cpkt.(*PUBCOMP)
			case TypeUNSUBACK:
				pkt, ok = cpkt.(*UNSUBACK)
			case TypePINGREQ:
				pkt, ok = cpkt.(*PINGREQ)
			}
			if !ok {
				t.Errorf("Unmarshal %v gave type %T, want %T", ByteSlice(test.encoded), pkt, test.expected)
			} else if !reflect.DeepEqual(pkt, test.expected) {
				t.Errorf("Unmarshal %v gave %+v, want %+v", ByteSlice(test.encoded), pkt, test.expected)
			}
		}
	}
}

/*******************************************************
*                      CONNACK                         *
********************************************************/

func TestMarshalCONNACK(t *testing.T) {
	tests := []struct {
		pkt      CONNACK
		expected []byte
	}{
		{CONNACK{false, 0}, []byte{0x20, 0x02, 0x00, 0x00}},
		{CONNACK{false, 4}, []byte{0x20, 0x02, 0x00, 0x04}},
		{CONNACK{false, 0x2e}, []byte{0x20, 0x02, 0x00, 0x2e}},
		{CONNACK{true, 5}, []byte{0x20, 0x02, 0x01, 0x05}},
		{CONNACK{true, 6}, []byte{0x20, 0x02, 0x01, 0x06}},
		{CONNACK{true, 0xf3}, []byte{0x20, 0x02, 0x01, 0xf3}},
	}

	var marshaled []byte
	for _, test := range tests {
		marshaled = test.pkt.Marshal()
		if !bytes.Equal(marshaled, test.expected) {
			t.Errorf("Packet %+v marshaled to %v, want %v", test.pkt, ByteSlice(marshaled), ByteSlice(test.expected))
		}
	}
}

func TestErrUnmarshalCONNACK(t *testing.T) {
	tests := []struct {
		encoded  []byte
		expected error
	}{
		{[]byte{0x27, 0x02, 0x01, 0x00}, ErrCONNACKFlags},        // Invalid Packet Flags
		{[]byte{0x20, 0x40, 0x00, 0x04}, ErrLengthMismatch},      // Remaining Length mismatch
		{[]byte{0x20, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrCONNACK}, // Extra data
		{[]byte{0x20, 0x02, 0x51, 0x03}, ErrCAckFlags},           // Invalid Connect Acknowledge flags
		{[]byte{0x20, 0x02, 0x01, 0x43}, ErrCONNACKReturnCode},   // Invalid Return code
	}

	for _, test := range tests {
		_, err := Unmarshal(test.encoded)
		if err == nil {
			t.Errorf("Unmarshal %v did not fail, want error '%v'", ByteSlice(test.encoded), test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with '%v', want '%v'", ByteSlice(test.encoded), err, test.expected)
		}
	}
}

func TestUnmarshalCONNACK(t *testing.T) {
	tests := []struct {
		encoded  []byte
		expected *CONNACK
	}{
		{[]byte{0x20, 0x02, 0x00, 0x04}, &CONNACK{false, 4}},
		{[]byte{0x20, 0x02, 0x01, 0x05}, &CONNACK{true, 5}},
		{[]byte{0x20, 0x02, 0x00, 0x00}, &CONNACK{false, 0}},
		{[]byte{0x20, 0x02, 0x01, 0x02}, &CONNACK{true, 2}},
	}

	for _, test := range tests {
		cpkt, err := Unmarshal(test.encoded)
		if err != nil {
			t.Errorf("Unmarshal %v errored '%v', want %+v", ByteSlice(test.encoded), err, test.expected)
		} else {
			switch pkt := cpkt.(type) {
			case *CONNACK:
				if !reflect.DeepEqual(pkt, test.expected) {
					t.Errorf("Unmarshal %v gave %v, want %+v", ByteSlice(test.encoded), *pkt, test.expected)
				}
			default:
				t.Errorf("Unmarshal %v gave type %T, want %T", ByteSlice(test.encoded), pkt, test.expected)
			}
		}
	}
}

/*******************************************************
*                       PUBACK                         *
********************************************************/

func TestMarshalPUBACK(t *testing.T) {
	testMarshalPacket(t, TypePUBACK, []byte{0x40, 0x02})
}

func TestErrUnmarshalPUBACK(t *testing.T) {
	tests := []struct {
		encoded  []byte
		expected error
	}{
		{[]byte{0x4c, 0x02, 0x13, 0x20}, ErrPUBACKFlags},                    // Invalid Packet Flags
		{[]byte{0x40, 0x31, 0x00, 0x04}, ErrLengthMismatch},                 // Remaining Length mismatch
		{[]byte{0x40, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrPUBACKExpectedSize}, // Extra data
		{[]byte{0x40, 0x02, 0x00, 0x00}, ErrPUBACKInvalidPacketID},          // Invalid Packet ID
	}

	for _, test := range tests {
		_, err := Unmarshal(test.encoded)
		if err == nil {
			t.Errorf("Unmarshal %v did not fail, want error '%v'", ByteSlice(test.encoded), test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with '%v', want '%v'", ByteSlice(test.encoded), err, test.expected)
		}
	}
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
	tests := []struct {
		encoded  []byte
		expected error
	}{
		{[]byte{0x5c, 0x02, 0x13, 0x20}, ErrPUBRECFlags},                    // Invalid Packet Flags
		{[]byte{0x50, 0x3c, 0x00, 0x04}, ErrLengthMismatch},                 // Remaining Length mismatch
		{[]byte{0x50, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrPUBRECExpectedSize}, // Extra data
		{[]byte{0x50, 0x02, 0x00, 0x00}, ErrPUBRECInvalidPacketID},          // Invalid Packet ID
	}

	for _, test := range tests {
		_, err := Unmarshal(test.encoded)
		if err == nil {
			t.Errorf("Unmarshal %v did not fail, want error '%v'", ByteSlice(test.encoded), test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with '%v', want '%v'", ByteSlice(test.encoded), err, test.expected)
		}
	}
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
	tests := []struct {
		encoded  []byte
		expected error
	}{
		{[]byte{0x63, 0x02, 0x13, 0x20}, ErrPUBRELFlags},                    // Invalid Packet Flags
		{[]byte{0x62, 0x63, 0x00, 0x04}, ErrLengthMismatch},                 // Remaining Length mismatch
		{[]byte{0x62, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrPUBRELExpectedSize}, // Extra data
		{[]byte{0x62, 0x02, 0x00, 0x00}, ErrPUBRELInvalidPacketID},          // Invalid Packet ID
	}

	for _, test := range tests {
		_, err := Unmarshal(test.encoded)
		if err == nil {
			t.Errorf("Unmarshal %v did not fail, want error '%v'", ByteSlice(test.encoded), test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with '%v', want '%v'", ByteSlice(test.encoded), err, test.expected)
		}
	}
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
	tests := []struct {
		encoded  []byte
		expected error
	}{
		{[]byte{0x7e, 0x02, 0x13, 0x20}, ErrPUBCOMPFlags},                    // Invalid Packet Flags
		{[]byte{0x70, 0x63, 0x00, 0x04}, ErrLengthMismatch},                  // Remaining Length mismatch
		{[]byte{0x70, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrPUBCOMPExpectedSize}, // Extra data
		{[]byte{0x70, 0x02, 0x00, 0x00}, ErrPUBCOMPInvalidPacketID},          // Invalid Packet ID
	}

	for _, test := range tests {
		_, err := Unmarshal(test.encoded)
		if err == nil {
			t.Errorf("Unmarshal %v did not fail, want error '%v'", ByteSlice(test.encoded), test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with '%v', want '%v'", ByteSlice(test.encoded), err, test.expected)
		}
	}
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
	tests := []struct {
		encoded  []byte
		expected error
	}{
		{[]byte{0xb5, 0x02, 0x13, 0x20}, ErrUNSUBACKFlags},                    // Invalid Packet Flags
		{[]byte{0xb0, 0x42, 0x00, 0x04}, ErrLengthMismatch},                   // Remaining Length mismatch
		{[]byte{0xb0, 0x04, 0x00, 0x05, 0x02, 0x04}, ErrUNSUBACKExpectedSize}, // Extra data
		{[]byte{0xb0, 0x02, 0x00, 0x00}, ErrUNSUBACKInvalidPacketID},          // Invalid Packet ID
	}

	for _, test := range tests {
		_, err := Unmarshal(test.encoded)
		if err == nil {
			t.Errorf("Unmarshal %v did not fail, want error '%v'", ByteSlice(test.encoded), test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with '%v', want '%v'", ByteSlice(test.encoded), err, test.expected)
		}
	}
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
	tests := []struct {
		encoded  []byte
		expected error
	}{
		{[]byte{0xce, 0x00}, ErrPINGREQFlags},                    // Invalid Packet Flags
		{[]byte{0xc0, 0x1e, 0x00, 0x04}, ErrLengthMismatch},      // Remaining Length mismatch
		{[]byte{0xc0, 0x02, 0x00, 0x05}, ErrPINGREQExpectedSize}, // Extra data
	}

	for _, test := range tests {
		_, err := Unmarshal(test.encoded)
		if err == nil {
			t.Errorf("Unmarshal %v did not fail, want error '%v'", ByteSlice(test.encoded), test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with '%v', want '%v'", ByteSlice(test.encoded), err, test.expected)
		}
	}
}

func TestUnmarshalPINGREQ(t *testing.T) {
	testUnmarshalPacket(t, TypePINGREQ, []byte{0xc0, 0x00})
}
