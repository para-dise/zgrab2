// Minecraft module to grab the server's MOTD and version
package minecraft2

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	_ "io"
	"log"
	"net"
	"os"
	"runtime"
	"time"
	_ "time"

	"unicode/utf16"

	"github.com/iverly/go-mcping/api/types"
	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	MaxTries      int  `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
	MaxTimeout    int  `long:"max-timeout" default:"2" description:"Number of seconds to wait before timing out."`
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
	Latency     string `json:"latency",omitempty`
	Protocol    string `json:"protocol"`
	Favicon     string `json:"favicon"`
	Motd        string `json:"motd"`
	Version     string `json:"version"`
	PlayerStats struct {
		MaxPlayers    int `json:"maxPlayers"`
		OnlinePlayers int `json:"onlinePlayers"`
	} `json:"playerstats"`
	Players []Player `json:"players",omitempty`
	ModList []FMLMod `json:"modlist",omitempty`
}

type Player struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type CustomPingResponse struct {
	Latency     uint                 // Latency between you and the server
	PlayerCount types.PlayerCount    // Players count information of the server
	Protocol    int                  // Protocol number of the server
	Favicon     string               // Favicon in base64 of the server
	Motd        string               // Motd of the server without color
	Version     string               // Version of the server
	Sample      []types.PlayerSample // List of connected players on the server
	ModList     []FMLMod             // List of FML mods on the server
}

type FMLMod struct {
	ModId   string `json:"modId"`
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

type Channel struct {
	Path     string
	Version  uint64
	Required bool
}

func decodeForgePayload(data []byte) ([]FMLMod, error) {
	// We'll collect all mods here
	var mods []FMLMod
	offset := 0

	// 1) Read boolean (truncation flag): 1 byte
	if offset+1 > len(data) {
		return nil, errors.New("not enough data for truncation boolean")
	}
	trunc := (data[offset] != 0)
	offset++

	// 2) Read short (big-endian) for modCount
	if offset+2 > len(data) {
		return nil, errors.New("not enough data for modCount short")
	}
	modCount := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 3) For each mod
	for i := 0; i < int(modCount); i++ {
		// read channelSizeAndVersionFlag as varint
		chSizeAndFlag, n, err := read_varint(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("failed reading channelSizeAndVersionFlag: %w", err)
		}
		offset += n
		isIgnoreServerOnly := (chSizeAndFlag & 1) == 1
		channelSize := chSizeAndFlag >> 1

		// read mod ID
		modID, n, err := read_mc_string(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("failed reading mod ID: %w", err)
		}
		offset += n

		var modVersion string
		if !isIgnoreServerOnly {
			modVersion, n, err = read_mc_string(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed reading mod version: %w", err)
			}
			offset += n
		}

		// read the channels
		channels := make([]Channel, 0, channelSize)
		for c := 0; c < int(channelSize); c++ {
			path, n, err := read_mc_string(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed reading channel path: %w", err)
			}
			offset += n

			ver, n, err := read_varint(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed reading channel version: %w", err)
			}
			offset += n

			req, n, err := read_bool(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed reading channel required: %w", err)
			}
			offset += n

			channels = append(channels, Channel{
				Path:     path,
				Version:  ver,
				Required: req,
			})

			//fmt.Println("Channel = ", path, ver, req)
		}

		mods = append(mods, FMLMod{
			ModId:   modID,
			Version: modVersion,
		})
		//fmt.Println("ModID = ", modID, modVersion)
	}

	// 4) If not truncated, read “non-mod” channels
	if !trunc {
		// read varint for the nonMod count
		nonModCount, n, err := read_varint(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("failed reading nonModCount: %w", err)
		}
		offset += n

		for i := 0; i < int(nonModCount); i++ {
			// resource location is just a MC string
			rl, n, err := read_mc_string(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed reading resource location: %w", err)
			}
			offset += n

			ver, n, err := read_varint(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed reading version: %w", err)
			}
			offset += n

			req, n, err := read_bool(data[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed reading bool: %w", err)
			}
			offset += n

			// TODO: Use this data
			_ = rl
			_ = ver
			_ = req
		}
	}

	return mods, nil
}

func decodeResponse(response string, hostAddress string) (*CustomPingResponse, error) {

	var panicErr error
	// prevent panics
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)

			// Get the traceback
			trace := make([]byte, 1<<16)
			n := runtime.Stack(trace, true)
			trace = trace[:n]

			// Write the traceback to a file
			file, err := os.Create("traceback_" + hostAddress + ".txt")
			if err != nil {
				fmt.Println("Error creating file:", err)
				return
			}
			defer file.Close()

			// append hostAddress to traceback
			trace = append([]byte(hostAddress+" - "), trace...)

			_, err = file.WriteString(string(trace))
			if err != nil {
				fmt.Println("Error writing to file:", err)
				return
			}

			// Set the error message
			panicErr = fmt.Errorf("Recovered in f: %v\nTraceback:\n%s", r, trace)
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

		var motd = ""
		if _, ok := dataMap["description"]; ok {
			// check if description is a map or a string (BungeeCord)
			if _, ok := dataMap["description"].(map[string]interface{}); ok {
				// if text exists under description, use it
				if _, ok := dataMap["description"].(map[string]interface{})["text"]; ok {
					motd = dataMap["description"].(map[string]interface{})["text"].(string)
				}
			} else {
				if _, ok := dataMap["description"].(string); ok {
					motd = dataMap["description"].(string)
				}
			}
		}

		// check if MOTD is empty, this is the case for BungeeCord & its forks
		if motd == "" {
			// if description is a map
			if _, ok := dataMap["description"].(map[string]interface{}); ok {
				if _, ok := dataMap["description"].(map[string]interface{})["extra"]; ok {
					if _, ok := dataMap["description"].(map[string]interface{})["extra"].([]interface{}); ok {
						extraArray := dataMap["description"].(map[string]interface{})["extra"].([]interface{})
						for _, value := range extraArray {
							// In some strange cases, the extra array contains strings

							// TODO: What if the extra array has both a string and a map?
							if _, ok := value.(string); ok {
								motd += value.(string)
								continue
							}

							if _, ok := value.(map[string]interface{})["text"]; ok {
								// if text is a string
								if _, ok := value.(map[string]interface{})["text"].(string); ok {
									motd += value.(map[string]interface{})["text"].(string)
								}
							}
						}
					}
				}
			} else {
				// if motd is an array of objects
				if _, ok := dataMap["description"].([]interface{}); ok {
					extraArray := dataMap["description"].([]interface{})
					for _, value := range extraArray {
						if _, ok := value.(map[string]interface{})["text"]; ok {
							// if text is a string
							if _, ok := value.(map[string]interface{})["text"].(string); ok {
								motd += value.(map[string]interface{})["text"].(string)
							}
						}
					}
				}
			}
		}

		if motd == "" {
			motd = "Unknown"
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

		// check if "modpackData" is present
		if _, ok := dataMap["modpackData"]; ok {
			// change "Version" to begin with "Fabric"
			version = "Fabric " + version

			fmlMod := FMLMod{}
			if _, ok := dataMap["modpackData"].(map[string]interface{})["name"]; ok {
				fmlMod.ModId = dataMap["modpackData"].(map[string]interface{})["name"].(string)
			}
			if _, ok := dataMap["modpackData"].(map[string]interface{})["version"]; ok {
				fmlMod.Version = dataMap["modpackData"].(map[string]interface{})["version"].(string)
			}
			forgeModList = append(forgeModList, fmlMod)
		}

		// apparently forge also uses "forgeData" now
		if _, ok := dataMap["forgeData"]; ok {
			// change "Version" to begin with "Forge"
			version = "Forge " + version
			// decompress forgeData "d" field
			if _, ok := dataMap["forgeData"].(map[string]interface{})["d"]; ok {
				decompressed := decodeOptimized(dataMap["forgeData"].(map[string]interface{})["d"].(string))
				// use forge's custom decoding
				mods, err := decodeForgePayload(decompressed.Bytes())
				if err != nil {
					fmt.Println("Error decoding forgeData:", err)
				} else {
					forgeModList = append(forgeModList, mods...)
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

// read_varint reads a varint from the given byte[]
func read_varint(data []byte) (uint64, int, error) {
	var value uint64
	var shift uint
	for i, b := range data {
		value |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return value, i + 1, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, 0, errors.New("varint is too long")
		}
	}
	return 0, 0, errors.New("incomplete varint")
}

// read_mc_string reads a “Minecraft-style” UTF string: first a VarInt length,
// then that many bytes of UTF-8 data.
func read_mc_string(data []byte) (value string, readLen int, err error) {
	length, n, err := read_varint(data)
	if err != nil {
		return "", 0, err
	}
	if length > uint64(len(data)-n) {
		return "", 0, errors.New("string length goes out of bounds")
	}
	start := n
	end := n + int(length)
	strData := data[start:end]
	return string(strData), end, nil
}

// read_bool reads a single byte (0 or 1) from data[offset]
func read_bool(data []byte) (val bool, readLen int, err error) {
	if len(data) < 1 {
		return false, 0, errors.New("not enough data for bool")
	}
	val = (data[0] != 0)
	return val, 1, nil
}

// decodeOptimized decodes a Java-style UTF-16 encoded string into a byte buffer.
func decodeOptimized(s string) *bytes.Buffer {
	// Decode UTF-16 from Go's UTF-8 string representation
	runes := []rune(s)                  // Convert to runes, which preserves UTF-16 semantics
	utf16Encoded := utf16.Encode(runes) // Convert to UTF-16 code units (uint16 array)

	if len(utf16Encoded) < 2 {
		return nil // Invalid input
	}

	// Extract size from the first two UTF-16 code units
	size0 := int(utf16Encoded[0])
	size1 := int(utf16Encoded[1])
	size := size0 | (size1 << 15)

	buf := bytes.NewBuffer(make([]byte, 0, size))

	stringIndex := 2
	buffer := 0 // Buffer for bits (22 bits max)
	bitsInBuf := 0

	// Process each UTF-16 code unit
	for stringIndex < len(utf16Encoded) {
		for bitsInBuf >= 8 {
			buf.WriteByte(byte(buffer))
			buffer >>= 8
			bitsInBuf -= 8
		}

		c := int(utf16Encoded[stringIndex])
		buffer |= (c & 0x7FFF) << bitsInBuf
		bitsInBuf += 15
		stringIndex++
	}

	// Write remaining bits to buffer
	for buf.Len() < size && bitsInBuf > 0 {
		buf.WriteByte(byte(buffer))
		buffer >>= 8
		bitsInBuf -= 8
	}

	return buf
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {

	hasPanic := false

	/* In case of a panic, recover and return a ScanError */
	defer func() {
		if r := recover(); r != nil {
			hasPanic = true
		}
	}()

	if hasPanic {
		panicErr := errors.New("Panic")
		return zgrab2.TryGetScanStatus(panicErr), nil, panicErr
	}

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

	var waitTime = 2 * time.Second
	if scanner.config.MaxTimeout != 0 {
		waitTime = time.Duration(scanner.config.MaxTimeout) * time.Second
	}

	ret, _ = zgrab2.ReadAvailableWithOptions(conn, 65535, waitTime, waitTime, 65535)
	defer conn.Close()

	if len(ret) < 3 {
		err = errors.New("error to small response")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// Length: varint, Packet ID: varint, Data: byte[]
	// attempt to read length of packet
	_, varint_size, err := read_varint(ret)
	if err != nil {
		err = errors.New("error reading varint (packet len)")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// truncate first varint
	ret = ret[varint_size:]
	// attempt to read packet ID
	_, varint_size, err = read_varint(ret)
	if err != nil {
		err = errors.New("error reading varint (packet id)")
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// truncate second varint
	ret = ret[varint_size:]

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

	decode, err := decodeResponse(string(ret), target.Host())
	// TODO: Add proper error handling

	if err != nil {
		err = errors.New("panic")
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	var scanLatency = ""
	if scanner.config.EnableLatency {
		scanLatency = getLatency(target.Host(), uint16(scanner.GetPort())).String()
	}

	return zgrab2.SCAN_SUCCESS, &Results{
		Latency:  scanLatency,
		Protocol: fmt.Sprintf("%d", decode.Protocol),
		Favicon:  decode.Favicon,
		Motd:     decode.Motd,
		Version:  decode.Version,
		PlayerStats: struct {
			MaxPlayers    int `json:"maxPlayers"`
			OnlinePlayers int `json:"onlinePlayers"`
		}{decode.PlayerCount.Max, decode.PlayerCount.Online},
		Players: ConvertPlayerSampleToPlayer(decode.Sample),
		ModList: decode.ModList,
	}, nil
}
