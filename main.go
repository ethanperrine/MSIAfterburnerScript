package main

import (
	"log"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"MSIAfterburnerScript/config"
	"MSIAfterburnerScript/watcher"
)

// runAfterburner executes the MSI Afterburner command.
func runAfterburner(exe, arg string) {
	cmd := exec.Command(exe, arg)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to launch Afterburner with profile %s: %v", arg, err)
	} else {
		log.Printf("Successfully applied Afterburner profile: %s", arg)
	}
}

// checkStateAndApplyProfile is the core logic for determining and applying a profile.
// It now uses the Overrides map in the config as the sole list of targets.
func checkStateAndApplyProfile(cfg *config.Config, currentProfile *string) {
	// The list of targets is now the keys of the Overrides map.
	// The watcher will prioritize the foreground application.
	activeTarget, isActive := watcher.FirstActiveTarget(cfg.Overrides)

	var desiredProfile string
	if isActive {
		profile := cfg.Overrides[activeTarget]
		if profile != "" {
			desiredProfile = profile
		} else {
			desiredProfile = cfg.ProfileOn
		}
	} else {
		desiredProfile = cfg.ProfileOff
	}

	if desiredProfile != *currentProfile {
		log.Printf("State change detected. Desired profile: %s.", desiredProfile)
		if isActive {
			log.Printf("Reason: Active target '%s' found.", activeTarget)
		} else {
			log.Printf("Reason: No active targets found.")
		}
		runAfterburner(cfg.AfterburnerPath, desiredProfile)
		*currentProfile = desiredProfile
	}
}

// startPollingMode runs the application by checking for targets on a timer.
func startPollingMode(cfg config.Config) {
	log.Println("Starting in Polling Mode.")
	var currentProfile string
	checkStateAndApplyProfile(&cfg, &currentProfile)
	ticker := time.NewTicker(time.Duration(cfg.DelaySeconds) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		reloadedCfg := config.Load()
		cfg.ProfileOn = reloadedCfg.ProfileOn
		cfg.ProfileOff = reloadedCfg.ProfileOff
		cfg.Overrides = reloadedCfg.Overrides
		cfg.AfterburnerPath = reloadedCfg.AfterburnerPath
		checkStateAndApplyProfile(&cfg, &currentProfile)
	}
}

// startEventMode runs the application by listening for system events.
func startEventMode(cfg config.Config) {
	log.Println("Starting in Event-Driven Mode.")
	var currentProfile string
	eventHandler := func() {
		reloadedCfg := config.Load()
		cfg.ProfileOn = reloadedCfg.ProfileOn
		cfg.ProfileOff = reloadedCfg.ProfileOff
		cfg.Overrides = reloadedCfg.Overrides
		cfg.AfterburnerPath = reloadedCfg.AfterburnerPath

		checkStateAndApplyProfile(&cfg, &currentProfile)
	}
	eventHandler()
	watcher.StartEventWatcher(eventHandler)
	select {}
}

func main() {
	log.SetFlags(log.Ltime)
	cfg := config.Load()
	// log.Println("Configuration loaded.")
	switch strings.ToLower(cfg.MonitoringMode) {
	case "poll":
		startPollingMode(cfg)
	case "event":
		startEventMode(cfg)
	default:
		log.Fatalf("Invalid monitoring_mode %q in config.json", cfg.MonitoringMode)
	}
}
