package gomqtt_test

import (
	"bytes"
	"reflect"
	"testing"

	. "github.com/kayboot/gomqtt"
)

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
			t.Errorf("Packet %v marshaled to %v, want %v", test.pkt, marshaled, test.expected)
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
			t.Errorf("Unmarshal %v did not fail, want error %v", test.encoded, test.expected)
		} else if err != test.expected {
			t.Errorf("Unmarshal %v failed with %v, want %v", test.encoded, err, test.expected)
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
			t.Errorf("Unmarshal %v errored '%v', want %v", test.encoded, err, test.expected)
		} else {
			switch pkt := cpkt.(type) {
			case *CONNACK:
				if !reflect.DeepEqual(pkt, test.expected) {
					t.Errorf("Unmarshal %v gave %v, want %v", test.encoded, *pkt, test.expected)
				}
			default:
				t.Errorf("Unmarshal %v gave type %T, want %T", test.encoded, pkt, test.expected)
			}
		}
	}
}
