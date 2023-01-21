// Minecraft module to grab the server's MOTD and version
package minecraft2

import (
	"github.com/zmap/zgrab2"
	"log"
	"github.com/iverly/go-mcping/api/types"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	_ "time"
	_ "io"
	"encoding/json"
	"time"
	"fmt"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	MaxTries int `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
	MaxTimeout int `long:"max-timeout" default:"1" description:"Number of seconds to wait before timing out."`
	EnableLatency bool `long:"enable-latency" description:"Enable latency measurement. May drastically increase scan time."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

type Results struct {
	Latency		string `json:"latency",omitempty`
	Protocol	string `json:"protocol"`
	Favicon		string `json:"favicon"`
	Motd		string `json:"motd"`
	Version		string `json:"version"`
	PlayerStats struct {
        MaxPlayers    int `json:"maxPlayers"`
        OnlinePlayers int `json:"onlinePlayers"`
    } `json:"playerstats"`
	Players []Player `json:"players",omitempty`
	ModList	 []FMLMod `json:"modlist",omitempty`
}

type Player struct {
    UUID  string `json:"uuid"`
    Name  string `json:"name"`
}

type CustomPingResponse struct {
	Latency     uint // Latency between you and the server
	PlayerCount types.PlayerCount // Players count information of the server
	Protocol    int // Protocol number of the server
	Favicon     string // Favicon in base64 of the server
	Motd        string // Motd of the server without color
	Version     string // Version of the server
	Sample      []types.PlayerSample // List of connected players on the server
	ModList	 []FMLMod // List of FML mods on the server
}

type FMLMod struct {
	ModId string `json:"modId"`
	Version string `json:"version"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("minecraft2", "minecraft2", module.Description(), 25565, &module)
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
	return "Grab Minecraft server info from the target host"
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
	return "minecraft"
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

func ConvertPlayerSampleToPlayer(playersSample []types.PlayerSample) []Player {
    var players []Player
    for _, sample := range playersSample {
        players = append(players, Player{UUID: sample.UUID, Name: sample.Name})
    }
    return players
}


func sendPacket(host string, port uint16, conn *net.Conn) {
	var dataBuf bytes.Buffer
	var finBuf bytes.Buffer

	writeProtocol(&dataBuf, "\x6D") // 1.9 protocol
	writeHost(&dataBuf, host)
	writePort(&dataBuf, port)
	dataBuf.Write([]byte("\x01")) // end of packet

	// Prepend packet length with data
	packetLength := []byte{uint8(dataBuf.Len())}
	finBuf.Write(append(packetLength, dataBuf.Bytes()...))

	// Sending packet
	(*conn).Write(finBuf.Bytes())
	(*conn).Write([]byte("\x01\x00"))
}

func writeProtocol(b *bytes.Buffer, protocol string) {
	b.Write([]byte("\x00")) // Packet ID
	b.Write([]byte(protocol))
}

func writeHost(b *bytes.Buffer, host string) {
	b.Write([]uint8{uint8(len(host))})
	b.Write([]byte(host))
}

func writePort(b *bytes.Buffer, port uint16) {
	a := make([]byte, 2)
	binary.BigEndian.PutUint16(a, port)
	b.Write(a)
}

func decodeResponse(response string) (*CustomPingResponse, error) {

	var panicErr error
	// prevent panics
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
			panicErr = fmt.Errorf("Recovered in f: %v", r)
		}
	}()

	if panicErr != nil {
		return nil, panicErr
	}

	// {"enforcesSecureChat":false,"description":{"text":"A Minecraft Server"},"players":{"max":20,"online":1,"sample":[{"id":"d331d3ab-cd55-3c58-ab6f-e75b1e27b6d0","name":"xSpeziato"}]},"version":{"name":"Paper 1.19.3","protocol":761}}
	var data interface{}
	json.Unmarshal([]byte(response), &data)

	if dataMap, ok := data.(map[string]interface{}); ok {
		// create new PingResponse
		pingResponse := CustomPingResponse{}


		// check if version field exists
		var version = "Unknown"
		if _, ok := dataMap["version"]; ok {
			// if name exists under version, use it
			if _, ok := dataMap["version"].(map[string]interface{})["name"]; ok {
				version = dataMap["version"].(map[string]interface{})["name"].(string)
			}
		}

		var motd = "Unknown"
		if _, ok := dataMap["description"]; ok {
			// check if description is a map or a string (BungeeCord)
			if _, ok := dataMap["description"].(map[string]interface{}); ok {
				// if text exists under description, use it
				if _, ok := dataMap["description"].(map[string]interface{})["text"]; ok {
					motd = dataMap["description"].(map[string]interface{})["text"].(string)
				}
			} else {
				motd = dataMap["description"].(string)
			}
		}
	
		// create new PlayerCount
		playerCount := types.PlayerCount{}

		// check if players field exists
		if _, ok := dataMap["players"]; ok {
			// check if max and online fields exist
			if _, ok := dataMap["players"].(map[string]interface{})["max"]; ok {
				playerCount.Max = int(dataMap["players"].(map[string]interface{})["max"].(float64))
			} else {
				playerCount.Max = -1
			}
			if _, ok := dataMap["players"].(map[string]interface{})["online"]; ok {
				playerCount.Online = int(dataMap["players"].(map[string]interface{})["online"].(float64))
			} else {
				playerCount.Online = -1
			}
		}

		// check if Protocol field exists
		var protocol = -1
		// if version exists
		if _, ok := dataMap["version"]; ok {
			// if protocol exists under version, use it
			if _, ok := dataMap["version"].(map[string]interface{})["protocol"]; ok {
				protocol = int(dataMap["version"].(map[string]interface{})["protocol"].(float64))
			}
		}
		
		// check if favicon field exists
		var favicon string
		if _, ok := dataMap["favicon"]; ok {
			favicon = dataMap["favicon"].(string)
		} else {
			favicon = ""
		}

		var playerSamples []types.PlayerSample
		// check if sample field exists under players
		if playersMap, ok := dataMap["players"].(map[string]interface{}); ok {
			if sample, ok := playersMap["sample"].([]interface{}); ok {
				for _, v := range sample {
					sample := types.PlayerSample{}
					if id, ok := v.(map[string]interface{})["id"].(string); ok {
						sample.UUID = id
					} else {
						sample.UUID = ""
					}
					if name, ok := v.(map[string]interface{})["name"].(string); ok {
						sample.Name = name
					} else {
						sample.Name = ""
					}
					playerSamples = append(playerSamples, sample)
				}
			}
		}

		// set fml
		var forgeModList []FMLMod
		if _, ok := dataMap["modinfo"]; ok {
			// check if modinfo["modList"] exists
			if modList, ok := dataMap["modinfo"].(map[string]interface{})["modList"].([]interface{}); ok {
				for _, v := range modList {
					// create new FMLMod
					fmlMod := FMLMod{}
					if modid, ok := v.(map[string]interface{})["modid"].(string); ok {
						fmlMod.ModId = modid
					} else {
						fmlMod.ModId = ""
					}

					if version, ok := v.(map[string]interface{})["version"].(string); ok {
						fmlMod.Version = version
					} else {
						fmlMod.Version = ""
					}

					forgeModList = append(forgeModList, fmlMod)
				}
			}
		}


		pingResponse.Latency = 0
		pingResponse.PlayerCount = playerCount
		pingResponse.Protocol = protocol
		pingResponse.Favicon = favicon
		pingResponse.Motd = motd
		pingResponse.Version = version
		pingResponse.Sample = playerSamples
		pingResponse.ModList = forgeModList

		return &pingResponse, nil
	} else {
		return nil, errors.New("Invalid JSON response")
	}
}

/***
 * Function to get the latency of a Minecraft server (in milliseconds)
 * Connects via tcp and returns the time it took to connect
 * @param host string
 * @param port uint16
 * @return time.Duration
 */
func getLatency(host string, port uint16) time.Duration {
	// start timer
	start := time.Now()
	// connect to server
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return -1
	}
	// close connection
	conn.Close()
	// return time it took to connect
	return time.Since(start)
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {

	/* Begin new Minecraft scan */
	var (
		conn net.Conn
		err  error
		ret  []byte
	)

	// Connect to the server
	conn, err = target.Open(&scanner.config.BaseFlags)
	
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	sendPacket(target.Host(), uint16(scanner.GetPort()), &conn)
	
	var waitTime = 1 * time.Second
	if scanner.config.Timeout != 0 {
		waitTime = time.Duration(scanner.config.Timeout) * time.Second
	}

	ret, _ = zgrab2.ReadAvailableWithOptions(conn, 65535, waitTime, waitTime, 65535)

	if len(ret) < 3 {
		err = errors.New("error to small response")
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// truncate first 2 bytes
	ret = ret[2:]
	// check for null byte
	if ret[0] != 0 {
		err = errors.New("error no null byte")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	if len(ret) < 10 {
		err = errors.New("error to small response")
		return zgrab2.TryGetScanStatus(err), nil, err
	} else if len(ret) > 700000 {
		err = errors.New("error to big response")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// remove all characters until the first '{'

	// check if '{' or '}' exists within the first 10 bytes
	if bytes.IndexByte(ret, '{') == -1 || bytes.IndexByte(ret, '}') == -1 {
		err = errors.New("error no json")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	ret = ret[bytes.IndexByte(ret, '{'):]
	// remove all characters after last '}'
	ret = ret[:bytes.LastIndexByte(ret, '}')+1]

	decode, err := decodeResponse(string(ret))

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	var scanLatency = ""
	if scanner.config.EnableLatency {
		scanLatency = getLatency(target.Host(), uint16(scanner.GetPort())).String()
	}

	return zgrab2.SCAN_SUCCESS, &Results {
		Latency:   scanLatency,
		Protocol:  fmt.Sprintf("%d", decode.Protocol),
		Favicon:   decode.Favicon,
		Motd:      decode.Motd,
		Version:   decode.Version,
		PlayerStats: struct {
			MaxPlayers    int `json:"maxPlayers"`
			OnlinePlayers int `json:"onlinePlayers"`
		}{decode.PlayerCount.Max, decode.PlayerCount.Online},
		Players: ConvertPlayerSampleToPlayer(decode.Sample),
		ModList: decode.ModList,
	}, nil
}
