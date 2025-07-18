package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

const configFile = "config.json"

type Config struct {
	AfterburnerPath string            `json:"afterburner_path"`
	ProfileOn       string            `json:"profile_on"`
	ProfileOff      string            `json:"profile_off"`
	DelaySeconds    int               `json:"delay_seconds"`
	MonitoringMode  string            `json:"monitoring_mode"`
	Overrides       map[string]string `json:"overrides"`
}

func defaultConfig() Config {
	return Config{
		AfterburnerPath: `C:\Program Files (x86)\MSI Afterburner\MSIAfterburner.exe`,
		ProfileOn:       "-Profile5",
		ProfileOff:      "-Profile1",
		DelaySeconds:    15,
		MonitoringMode:  "event",
		Overrides:       make(map[string]string),
	}
}

func validateProfileString(profile string) error {
	if profile == "" {
		return nil
	}
	if !strings.HasPrefix(profile, "-Profile") {
		return fmt.Errorf("invalid profile format: %q (must start with \"-Profile\")", profile)
	}
	numStr := strings.TrimPrefix(profile, "-Profile")
	if numStr == "" {
		return fmt.Errorf("invalid profile format: %q (missing number after prefix)", profile)
	}
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return fmt.Errorf("invalid profile number: %q (the part after \"-Profile\" is not a valid integer)", profile)
	}
	if num < 1 || num > 5 {
		return fmt.Errorf("invalid profile number: %q (number %d is out of the valid range of 1-5)", profile, num)
	}
	return nil
}

func Load() Config {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Configuration file not found. Creating %s with default values.", configFile)
		cfg := defaultConfig()
		file, err := os.Create(configFile)
		if err != nil {
			log.Fatalf("Fatal: Could not create config file %s: %v", configFile, err)
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Printf("Warning: Cannot close %s: %v", configFile, err)
			}
		}(file)
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "    ")
		if err := encoder.Encode(cfg); err != nil {
			log.Fatalf("Fatal: Could not write to config file %s: %v", configFile, err)
		}
		return cfg
	}

	var cfg Config
	file, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Fatal: Cannot open config file %s: %v", configFile, err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("Warning: Cannot close %s: %v", configFile, err)
		}
	}(file)

	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		log.Fatalf("Fatal: Could not parse config file %s. Please check for JSON syntax errors like a missing comma or quote. Details: %v", configFile, err)
	}

	if err := validateProfileString(cfg.ProfileOn); err != nil || cfg.ProfileOn == "" {
		log.Fatalf("Configuration error in 'profile_on'. A valid profile must be like \"-ProfileN\" where N is a number from 1 to 5. Details: %v", err)
	}
	if err := validateProfileString(cfg.ProfileOff); err != nil || cfg.ProfileOff == "" {
		log.Fatalf("Configuration error in 'profile_off'. A valid profile must be like \"-ProfileN\" where N is a number from 1 to 5. Details: %v", err)
	}
	mode := strings.ToLower(cfg.MonitoringMode)
	if mode != "poll" && mode != "event" {
		log.Fatalf("Configuration error: 'monitoring_mode' must be either \"poll\" or \"event\", but found %q. Please correct the value in %s.", cfg.MonitoringMode, configFile)
	}
	for target, profile := range cfg.Overrides {
		delete(cfg.Overrides, target)
		cfg.Overrides[strings.ToLower(target)] = profile
		if err := validateProfileString(profile); err != nil {
			log.Fatalf("Configuration error in 'overrides' for target %q. The profile must be like \"-ProfileN\" (where N is 1-5) or an empty string \"\" to use the default 'On' profile. Details: %v", target, err)
		}
	}

	return cfg
}
