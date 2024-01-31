// Minecraft module to grab the server's MOTD and version
package bedrock

import (
	"github.com/zmap/zgrab2"
    "net"
	"encoding/binary"
    "strings"
	"log"
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// Network Util Functions

// ReadBigInt64BE reads a big-endian encoded int64 from the buffer at the specified offset.
func ReadBigInt64BE(buffer []byte, offset int) int64 {
    return int64(binary.BigEndian.Uint64(buffer[offset:]))
}

// ReadStringFromBuffer reads a string from the buffer at the specified offset.
func ReadStringFromBuffer(buffer []byte, offset int) string {
    length := int(binary.BigEndian.Uint16(buffer[offset:]))
    return string(buffer[offset+2 : offset+2+length])
}

// ParseAdvertiseString parses the advertise string into a struct.
func ParseAdvertiseString(advertiseStr string) (*AdvertiseData, error) {
	parts := strings.Split(advertiseStr, ";")
	if len(parts) < 9 {
		return nil, errors.New("host did not return enough data")
	}

	return &AdvertiseData{
		GameID:         parts[0],
		Description:    parts[1],
		ProtocolVersion: parts[2],
		GameVersion:    parts[3],
		CurrentPlayers: parts[4],
		MaxPlayers:     parts[5],
		Name:           parts[7],
		Mode:           parts[8],
	}, nil
}

// AdvertiseData represents the parsed advertise data.
type AdvertiseData struct {
    GameID         string
    Description    string
    ProtocolVersion string
    GameVersion    string
    CurrentPlayers string
    MaxPlayers     string
    Name           string
    Mode           string
}

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
	MaxTries int `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

type Results struct {
	GameID		string `json:"gameid"`
	Description	string `json:"description"`
	ProtocolVersion		string `json:"protocol"`
	GameVersion		string `json:"version"`
	PlayerStats struct {
        MaxPlayers    int `json:"maxPlayers"`
        OnlinePlayers int `json:"onlinePlayers"`
    } `json:"playerstats"`
	Name	string `json:"name"`
	Mode 	string `json:"mode"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("bedrock", "bedrock", module.Description(), 19132, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Read the Minecraft Bedrock Ping Packet from the server."
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "bedrock"
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

func Receive(sock net.Conn) (int, []byte, error) {
	var received int
	ReceiveChunkSize := 8192
	buffer := bytes.NewBuffer(nil)
	for {
	  chunk := make([]byte, ReceiveChunkSize)
	  read, err := sock.Read(chunk)
	  if err != nil {
		return received, buffer.Bytes(), err
	  }
	  received += read
	  buffer.Write(chunk[:read])
  
	  if read == 0 || read < ReceiveChunkSize {
		break
	  }
	}
	return received, buffer.Bytes(), nil
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var panicErr error // this seems to not really work, but we do recover from panics in the main loop

    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from panic:", r)
            panicErr = fmt.Errorf("panic occurred: %v", r)
        }
    }()

    sock, err := target.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
    if err != nil {
        return zgrab2.TryGetScanStatus(err), nil, err
    }
    defer sock.Close()

    result := &Results{}
	for i := 0; i < scanner.config.MaxTries; i++ {
		// Send packet
		_, err = sock.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		// recv
		buffer := make([]byte, 65535)
		length, err := sock.Read(buffer)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		buffer = buffer[:length]

		// Process response
		bufData := ReadStringFromBuffer(buffer, 25)
		parsedData, err := ParseAdvertiseString(bufData)

		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}

		// convert CurrentPlayers and MaxPlayers to PlayerStats[MaxPlayers, OnlinePlayers]
		playerstats := struct {
			MaxPlayers    int `json:"maxPlayers"`
			OnlinePlayers int `json:"onlinePlayers"`
		}{}
		
		playerstats.MaxPlayers, _ = strconv.Atoi(parsedData.MaxPlayers)
		playerstats.OnlinePlayers, _ = strconv.Atoi(parsedData.CurrentPlayers)

		// return Results struct
		result.GameID = parsedData.GameID
		result.Description = parsedData.Description
		result.ProtocolVersion = parsedData.ProtocolVersion
		result.GameVersion = parsedData.GameVersion
		result.PlayerStats = playerstats
		result.Name = parsedData.Name
		result.Mode = parsedData.Mode

		break
	}

	if panicErr != nil {
        return zgrab2.SCAN_PROTOCOL_ERROR, nil, panicErr
    }

    return zgrab2.SCAN_SUCCESS, result, nil
}
