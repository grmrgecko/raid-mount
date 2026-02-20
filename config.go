package main

import (
	"encoding/json"
	"log"
	"os"
	"os/user"
	"path/filepath"
)

// Config holds the application configuration.
type Config struct {
	RaidTablePath string   `json:"raid_table_path"`
	Services      []string `json:"services"`

	EncryptionKey string `json:"encryption_key"`
}

// ReadConfig reads and parses the configuration file.
func (a *App) ReadConfig() {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	// Configuration paths.
	localConfig, _ := filepath.Abs("./config.json")
	homeDirConfig := usr.HomeDir + "/.config/raid-mount/config.json"
	etcConfig := "/etc/raid-mount/config.json"

	// Default config.
	app.config = Config{
		RaidTablePath: "/etc/raid-mount/raidtab",
	}

	// Determine which configuration to use.
	var configFile string
	if app.flags.ConfigPath != "" {
		if _, err := os.Stat(app.flags.ConfigPath); err != nil {
			log.Fatalln("Specified configuration file does not exist:", app.flags.ConfigPath)
		}
		configFile = app.flags.ConfigPath
	} else {
		// Search standard paths in priority order.
		for _, candidate := range []string{localConfig, homeDirConfig, etcConfig} {
			if _, err := os.Stat(candidate); err == nil {
				configFile = candidate
				break
			}
		}
		if configFile == "" {
			log.Println("Unable to find a configuration file.")
			return
		}
	}

	jsonFile, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("Error reading JSON file: %s\n", err)
		return
	}

	err = json.Unmarshal(jsonFile, &app.config)
	if err != nil {
		log.Printf("Error parsing JSON file: %s\n", err)
	}
}
