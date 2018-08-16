package gomqtt_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	. "github.com/kayboot/gomqtt"
)

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
	tests := []struct {
		pkt      PUBACK
		expected []byte
	}{
		{PUBACK{0x233e}, []byte{0x40, 0x02, 0x23, 0x3e}},
		{PUBACK{0x6477}, []byte{0x40, 0x02, 0x64, 0x77}},
		{PUBACK{0x4f00}, []byte{0x40, 0x02, 0x4f, 0x00}},
		{PUBACK{0xfadb}, []byte{0x40, 0x02, 0xfa, 0xdb}},
		{PUBACK{0x0042}, []byte{0x40, 0x02, 0x00, 0x42}},
		{PUBACK{0x0000}, []byte{0x40, 0x02, 0x00, 0x00}},
	}

	var marshaled []byte
	for _, test := range tests {
		marshaled = test.pkt.Marshal()
		if !bytes.Equal(marshaled, test.expected) {
			t.Errorf("Packet %+v marshaled to %v, want %v", test.pkt, ByteSlice(marshaled), ByteSlice(test.expected))
		}
	}
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
	tests := []struct {
		encoded  []byte
		expected *PUBACK
	}{
		{[]byte{0x40, 0x02, 0x00, 0x04}, &PUBACK{0x0004}},
		{[]byte{0x40, 0x02, 0x25, 0xf5}, &PUBACK{0x25f5}},
		{[]byte{0x40, 0x02, 0x11, 0x00}, &PUBACK{0x1100}},
		{[]byte{0x40, 0x02, 0x10, 0x35}, &PUBACK{0x1035}},
	}

	for _, test := range tests {
		cpkt, err := Unmarshal(test.encoded)
		if err != nil {
			t.Errorf("Unmarshal %v errored '%v', want %+v", ByteSlice(test.encoded), err, test.expected)
		} else {
			switch pkt := cpkt.(type) {
			case *PUBACK:
				if !reflect.DeepEqual(pkt, test.expected) {
					t.Errorf("Unmarshal %v gave %+v, want %+v", ByteSlice(test.encoded), *pkt, test.expected)
				}
			default:
				t.Errorf("Unmarshal %v gave type %T, want %T", ByteSlice(test.encoded), pkt, test.expected)
			}
		}
	}
}
