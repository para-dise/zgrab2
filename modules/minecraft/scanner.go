// Minecraft module to grab the server's MOTD and version
package minecraft

import (
	_ "fmt"
	"github.com/zmap/zgrab2"
	"log"
	"github.com/iverly/go-mcping/mcping"
	"github.com/iverly/go-mcping/api/types"
	"strconv"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
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
	Latency		string `json:"latency"`
	Protocol	string `json:"protocol"`
	Favicon		string `json:"protocol"`
	Motd		string `json:"motd"`
	Version		string `json:"version"`
	PlayerStats struct {
        MaxPlayers    int `json:"maxPlayers"`
        OnlinePlayers int `json:"onlinePlayers"`
    } `json:"playerstats"`
	Players []Player `json:"players",omitempty`
}

type Player struct {
    UUID  string `json:"uuid"`
    Name  string `json:"name"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("minecraft", "minecraft", module.Description(), 25565, &module)
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
	return "Read the Minecraft MOTD from the server."
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

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// Begin Minecraft scan
	pinger := mcping.NewPinger()
	res, err := pinger.Ping(target.Host(), uint16(scanner.GetPort()))

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	return zgrab2.SCAN_SUCCESS, &Results{
		Latency:   strconv.FormatUint(uint64(res.Latency), 10),
		Protocol:  strconv.FormatUint(uint64(res.Protocol), 10),
		Favicon:   res.Favicon,
		Motd:      res.Motd,
		Version:   res.Version,
		PlayerStats: struct {
			MaxPlayers    int `json:"maxPlayers"`
			OnlinePlayers int `json:"onlinePlayers"`
		}{res.PlayerCount.Max, res.PlayerCount.Online},
		Players: ConvertPlayerSampleToPlayer(res.Sample),
	}, nil
}
