package minecraft

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// packetData holds the data of a Minecraft packet.
type packetData struct {
	h       *packet.Header
	full    []byte
	payload *bytes.Buffer
}

// parseData parses the packet data slice passed into a packetData struct.
func parseData(data []byte, conn *Conn) (*packetData, error) {
	buf := bytes.NewBuffer(data)
	header := &packet.Header{}
	if err := header.Read(buf); err != nil {
		// We don't return this as an error as it's not in the hand of the user to control this. Instead,
		// we return to reading a new packet.
		return nil, fmt.Errorf("read packet header: %w", err)
	}
	if conn.packetFunc != nil {
		// The packet func was set, so we call it.
		conn.packetFunc(*header, buf.Bytes(), conn.RemoteAddr(), conn.LocalAddr())
	}
	return &packetData{h: header, full: data, payload: buf}, nil
}

// CreateHighLoadPacket creates a packet designed to be resource intensive for testing purposes
// This should only be used on servers you own for stress testing
func CreateHighLoadPacket(packetID uint32, size int) *bytes.Buffer {
	header := &packet.Header{
		PacketID: packetID,
	}

	// Create a buffer with the specified size
	buf := bytes.NewBuffer(make([]byte, 0, size+20)) // Add extra space for header

	// Write the header
	header.Write(buf)

	// Fill the payload with random-like data that's harder to compress
	payload := make([]byte, size)
	for i := 0; i < size; i++ {
		// Use a pattern that's not easily compressible
		payload[i] = byte((i * 17) % 256)
	}

	buf.Write(payload)
	return buf
}

// CreateComplexPacket creates a packet with complex structures that require more processing
func CreateComplexPacket(packetID uint32, complexity int) *bytes.Buffer {
	header := &packet.Header{
		PacketID: packetID,
	}

	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	header.Write(buf)

	// Create complex nested structures that are harder to process
	for i := 0; i < complexity; i++ {
		// Add length-prefixed strings (common in MC protocol)
		strLength := uint16(100) // 100 byte strings
		buf.Write([]byte{byte(strLength & 0xff), byte(strLength >> 8)})

		// Fill with semi-random data
		for j := 0; j < int(strLength); j++ {
			buf.WriteByte(byte((i + j) % 256))
		}

		// Add some VarInts (variable length integers used in MC protocol)
		// These take more CPU to decode
		writeVarInt(buf, int32(i*10000))
	}

	return buf
}

// Helper function to write VarInts (Minecraft protocol format)
func writeVarInt(buf *bytes.Buffer, val int32) {
	for {
		temp := byte(val & 0x7F)
		val >>= 7
		if val != 0 {
			temp |= 0x80
		}
		buf.WriteByte(temp)
		if val == 0 {
			break
		}
	}
}

type unknownPacketError struct {
	id uint32
}

func (err unknownPacketError) Error() string {
	return fmt.Sprintf("unexpected packet (ID=%v)", err.id)
}

// decode decodes the packet payload held in the packetData and returns the packet.Packet decoded.
func (p *packetData) decode(conn *Conn) (pks []packet.Packet, err error) {
	// Attempt to fetch the packet with the right packet ID from the pool.
	pkFunc, ok := conn.pool[p.h.PacketID]
	var pk packet.Packet
	if !ok {
		// No packet with the ID. This may be a custom packet of some sorts.
		pk = &packet.Unknown{PacketID: p.h.PacketID}
		if conn.disconnectOnUnknownPacket {
			_ = conn.Close()
			return nil, unknownPacketError{id: p.h.PacketID}
		}
	} else {
		pk = pkFunc()
	}

	defer func() {
		if recoveredErr := recover(); recoveredErr != nil {
			err = fmt.Errorf("decode packet %T: %w", pk, recoveredErr.(error))
		}
		if err != nil && !errors.Is(err, unknownPacketError{}) && conn.disconnectOnInvalidPacket {
			_ = conn.Close()
		}
	}()

	r := conn.proto.NewReader(p.payload, conn.shieldID.Load(), conn.readerLimits)
	pk.Marshal(r)
	if p.payload.Len() != 0 {
		err = fmt.Errorf("decode packet %T: %v unread bytes left: 0x%x", pk, p.payload.Len(), p.payload.Bytes())
	}
	if conn.disconnectOnInvalidPacket && err != nil {
		return nil, err
	}
	return conn.proto.ConvertToLatest(pk, conn), err
}
