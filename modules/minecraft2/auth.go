package minecraft2

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	ErrVarintTooLong  = errors.New("varint is too long")
	ErrVarintTooShort = errors.New("varint is too short")
	STATE_STATUS      = 1
	STATE_LOGIN       = 2
	ErrTimeout        = errors.New("timeout waiting for auth mode")
	ErrDisconnected   = errors.New("disconnected by server")
	ErrInvalidPacket  = errors.New("invalid packet format")
)

type ConnectionData struct {
	State int
}

type varintReadResult struct {
	value int
	bytes []byte
}

func packVarint(val int) []byte {
	var buf [10]byte // max length of VarInt is 5 bytes for 32-bit, 10 for 64-bit
	i := 0
	for {
		b := byte(val & 0x7F)
		val >>= 7
		if val != 0 {
			buf[i] = b | 0x80
		} else {
			buf[i] = b
			break
		}
		i++
	}
	return buf[:i+1]
}

// packString encodes a UTF-8 string as VarInt length + bytes
func packString(s string) []byte {
	strBytes := []byte(s)
	var out []byte
	out = append(out, packVarint(len(strBytes))...)
	out = append(out, strBytes...)
	return out
}

// packByteArray => VarInt length + raw bytes
func packByteArray(b []byte) []byte {
	out := append(packVarint(len(b)), b...)
	return out
}

func sendHandshakeWithParams(conn net.Conn, c *ConnectionData, host string, port uint16, protocolVersion int) error {
	var buf bytes.Buffer
	buf.Write(packVarint(0x00))            // handshake packet ID
	buf.Write(packVarint(protocolVersion)) // protocol version
	buf.Write(packString(host))            // hostname
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	buf.Write(portBytes)     // port
	buf.Write(packVarint(2)) // next state = 2 (login)

	data := packVarint(buf.Len())
	data = append(data, buf.Bytes()...)

	_, err := conn.Write(data)
	return err
}

func readVarint(b []byte) (varintReadResult, error) {
	value := 0
	for i, byteValue := range b {
		value |= int(byteValue&0x7F) << (7 * i)
		if byteValue&0x80 == 0 {
			return varintReadResult{value: value, bytes: b[:i+1]}, nil
		}
		if i == 4 { // Varint is at most 5 bytes long
			return varintReadResult{}, ErrVarintTooLong
		}
	}
	return varintReadResult{}, ErrVarintTooShort
}

// parseUUID returns a big-endian 16-byte representation of the hex-dash string
func parseUUID(uuid string) ([]byte, error) {
	trim := strings.ReplaceAll(uuid, "-", "")
	if len(trim) != 32 {
		return nil, fmt.Errorf("invalid UUID format: %s", uuid)
	}
	raw, err := hex.DecodeString(trim)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func sendLoginStart(conn net.Conn, c *ConnectionData, botUsername string, botUUID string, activeProtocolVersion int) error {
	// 1.8 - 1.18.2: username only (47 - 758)
	// 1.19: username, Has Sig Data (759)
	// 1.19.2: username, Has Sig Data, has UUID, uuid (760)
	// 1.19.3 - 1.20.1: username, has UUID, uuid (761 - 763)
	// 1.20.2+: username, uuid (764+)

	var buf bytes.Buffer
	buf.Write(packVarint(0x00))        // packet id
	buf.Write(packString(botUsername)) // username

	if activeProtocolVersion >= 47 && activeProtocolVersion <= 758 {
		// 1.8 - 1.18.2: username only
	} else if activeProtocolVersion == 759 {
		// 1.19: username, Has Sig Data only
		buf.WriteByte(0x00) // Has Sig Data field (false)
	} else if activeProtocolVersion == 760 {
		// 1.19.2: username, Has Sig Data, has UUID, uuid
		buf.WriteByte(0x00) // Has Sig Data field (false)
		buf.WriteByte(0x01) // has UUID field (true)
		uuidBytes, err := parseUUID(botUUID)
		if err != nil {
			return fmt.Errorf("failed to parse UUID: %w", err)
		}
		buf.Write(uuidBytes)
	} else if activeProtocolVersion >= 761 && activeProtocolVersion <= 763 {
		// 1.19.3 - 1.20.1: username, has uuid field, uuid (no Has Sig Data)
		buf.WriteByte(0x01) // has UUID field (true)
		uuidBytes, err := parseUUID(botUUID)
		if err != nil {
			return fmt.Errorf("failed to parse UUID: %w", err)
		}
		buf.Write(uuidBytes)
	} else if activeProtocolVersion >= 764 {
		// 1.20.2+: username, uuid (no Has Sig Data, no has uuid field)
		uuidBytes, err := parseUUID(botUUID)
		if err != nil {
			return fmt.Errorf("failed to parse UUID: %w", err)
		}
		buf.Write(uuidBytes)
	}

	packet := buf.Bytes()
	fullPacket := append(packVarint(len(packet)), packet...)
	_, err := conn.Write(fullPacket)
	if err != nil {
		return fmt.Errorf("failed to send login start: %w", err)
	}
	return nil
}

func readLoop(ctx context.Context, conn net.Conn, c *ConnectionData, result chan<- int, errChan chan<- error) {
	defer func() {
		if r := recover(); r != nil {
			// Ensure channels are properly handled even during panic
			select {
			case errChan <- fmt.Errorf("panic in readLoop: %v", r):
			case <-ctx.Done():
			}
		}
	}()

	buf := make([]byte, 0, 5) // VarInt max is 5 bytes
	tmp := make([]byte, 1)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			select {
			case errChan <- fmt.Errorf("failed to set read deadline: %w", err):
			case <-ctx.Done():
			}
			return
		}

		buf = buf[:0]
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			_, err := conn.Read(tmp)
			if err != nil {
				netErr, ok := err.(net.Error)
				if ok && netErr.Timeout() {
					continue // Skip timeout errors and retry
				}
				if errors.Is(err, io.EOF) || isClosedConnError(err) {
					select {
					case errChan <- ErrDisconnected:
					case <-ctx.Done():
					}
					return
				}
				select {
				case errChan <- fmt.Errorf("error reading packet length: %w", err):
				case <-ctx.Done():
				}
				return
			}

			buf = append(buf, tmp[0])
			if tmp[0]&0x80 == 0 {
				break
			}
			if len(buf) > 5 {
				select {
				case errChan <- ErrVarintTooLong:
				case <-ctx.Done():
				}
				return
			}
		}

		lengthVarint, err := readVarint(buf)
		if err != nil {
			select {
			case errChan <- fmt.Errorf("error decoding packet length: %w", err):
			case <-ctx.Done():
			}
			return
		}

		packetLen := lengthVarint.value
		if packetLen < 0 || packetLen > 1024*1024 {
			select {
			case errChan <- fmt.Errorf("invalid packet length: %d", packetLen):
			case <-ctx.Done():
			}
			return
		}

		packetData := make([]byte, packetLen)
		_, err = io.ReadFull(conn, packetData)
		if err != nil {
			if errors.Is(err, io.EOF) || isClosedConnError(err) {
				select {
				case errChan <- ErrDisconnected:
				case <-ctx.Done():
				}
				return
			}
			select {
			case errChan <- fmt.Errorf("error reading packet body: %w", err):
			case <-ctx.Done():
			}
			return
		}

		if len(packetData) == 0 {
			select {
			case errChan <- ErrInvalidPacket:
			case <-ctx.Done():
			}
			return
		}

		packetIDResult, err := readVarint(packetData)
		if err != nil {
			select {
			case errChan <- fmt.Errorf("error decoding packet ID: %w", err):
			case <-ctx.Done():
			}
			return
		}
		packetID := packetIDResult.value

		switch packetID {
		case 0x01:
			select {
			case result <- 1:
			case <-ctx.Done():
			}
			return
		case 0x02, 0x03:
			select {
			case result <- 0:
			case <-ctx.Done():
			}
			return
		case 0x00:
			select {
			case result <- 2:
			case <-ctx.Done():
			}
			return
		}
	}
}

// Helper function to check for closed connection errors
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}

	str := err.Error()
	if strings.Contains(str, "use of closed network connection") ||
		strings.Contains(str, "connection reset by peer") ||
		strings.Contains(str, "connection refused") {
		return true
	}
	return false
}

func getAuthMode(conn net.Conn, protocolVersion int, host string, port uint16) (int, error) {
	defer conn.SetDeadline(time.Time{}) // Clear deadline when done

	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return -1, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	connection := &ConnectionData{
		State: STATE_STATUS,
	}

	if err := sendHandshakeWithParams(conn, connection, host, port, protocolVersion); err != nil {
		return -1, fmt.Errorf("failed to send handshake: %w", err)
	}

	if err := sendLoginStart(conn, connection, "MCScans", "00000000-0000-0000-0000-000000000000", protocolVersion); err != nil {
		return -1, fmt.Errorf("failed to send login start: %w", err)
	}
	connection.State = STATE_LOGIN

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authMode := make(chan int, 1)
	errChan := make(chan error, 1)

	// Use a wait group to ensure goroutine completes
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer func() {
			// Ensure channels are closed if goroutine exits unexpectedly
			select {
			case <-authMode: // already closed
			default:
				close(authMode)
			}
			select {
			case <-errChan: // already closed
			default:
				close(errChan)
			}
		}()
		readLoop(ctx, conn, connection, authMode, errChan)
	}()

	defer wg.Wait() // Ensure goroutine completes before returning

	select {
	case <-ctx.Done():
		return -1, ErrTimeout
	case mode, ok := <-authMode:
		if !ok {
			return -1, fmt.Errorf("auth mode channel closed unexpectedly")
		}
		return mode, nil
	case err, ok := <-errChan:
		if !ok {
			return -1, fmt.Errorf("error channel closed unexpectedly")
		}
		return -1, err
	}
}
