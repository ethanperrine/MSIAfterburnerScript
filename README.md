# MSIAfterburnerScript
A smart, event-driven utility for Windows that automatically applies MSI Afterburner profiles based on the application you are currently using.

## Description
MSIAfterburnerScript is a lightweight, background utility designed to automate your system's overclocking profiles. Instead of keeping your computer's GPU constantly overclocked, this script intelligently applies specific MSI Afterburner profiles only when a designated application is running and in focus.

When you launch a game or a demanding application from your configured list, the script instantly applies your "On" profile. When you switch to another application or close the target application, it seamlessly reverts to your "Off" profile. This ensures you get maximum performance when you need it and maintain efficiency and lower temperatures when you don't.

If multiple target applications are open, the script is smart enough to apply the correct profile for the application that is currently selected and in the foreground.

## Features
* **Dynamic Profile Switching:** Automatically applies overclocking profiles when a target application is active and reverts when it's not.
* **Foreground Priority:** Intelligently detects which application is currently in use and applies its specific profile, even with multiple target apps open.
* **Highly Configurable:** All settings, including Afterburner's path, profiles, and target applications, are managed in a simple config.json file.
* **Two Monitoring Modes:**
    * **Event (Default):** An efficient, instant-reaction mode that uses system event hooks to detect application changes with no delay.
    * **Poll:** A fallback mode that checks for active applications on a timed interval.
* **Partial Matching:** Detects applications even if the keyword in your config is only part of the process name or window title (e.g., "mygame" will match "mygame.exe").
* **Run as Administrator:** Includes an embedded manifest to ensure it always runs with the necessary permissions to control MSI Afterburner.

## How It Works
The application runs a continuous monitoring loop with the following priority:

1. **Foreground Check:** It first checks if the currently active (foreground) window or its process name contains a keyword from your `overrides` list. If it does, the corresponding profile is applied.
2. **Background Check:** If the foreground application is not a target, it scans all running processes and visible windows to see if any of them contain a target keyword. This is useful for background tasks.
3. **Default State:** If no target applications are found, it applies the default `profile_off`.

The application is state-aware and will only send a command to MSI Afterburner when a profile change is actually needed, preventing redundant actions.

## Installation & Setup
### Prerequisites
_I have included the downloadable binaries for Windows, but if you want to build it yourself, you will need the following:_
1. **Go:** You must have Go (version 1.21 or newer) installed. You can download it from the [official Go website](https://go.dev/dl/).
2. **MSI Afterburner:** This utility requires MSI Afterburner to be installed and configured with at least two saved profiles (_e.g., Profile 1 for idle, Profile 5 for gaming_).

### Building the Application
1. **Clone or Download:** Get the project files onto your computer. 
2. **Install Resource Tool:** The project uses a manifest to request administrator privileges. You need `go-rsrc` to embed it. Install it with:
`go install github.com/akavel/rsrc@latest`
3. **Generate Resource File:** In the project's root directory, run `rsrc` to create the `.syso` file that the Go compiler will automatically embed:
`rsrc -manifest main.manifest -o main.syso`
4. Build the Executable:
   * To build a version that runs silently in the background (recommended for deployment), use this command:
`go build -ldflags="-H windowsgui"`
   * To build a version with a visible console for debugging, use the standard build command:
`go build`

## Configuration
The application is controlled by the `config.json` file, which will be created with default values on the first run.

```json
{
    "afterburner_path": "C:\\Program Files (x86)\\MSI Afterburner\\MSIAfterburner.exe",
    "profile_on": "-Profile5",
    "profile_off": "-Profile1",
    "delay_seconds": 15,
    "monitoring_mode": "event",
    "overrides": {
        "mygame": "-Profile5",
        "another_app.exe": "-Profile4",
        "My Window Title": ""
    }
}
```

* **afterburner_path:** The full path to your MSIAfterburner.exe. You must use double backslashes (\\) in the path.
* **profile_on:** The default profile to apply when a target application is found but doesn't have a specific override.
* **profile_off:** The profile to apply when no target applications are active.
* **delay_seconds:** (Only used in poll mode) The number of seconds to wait between checks.
* **monitoring_mode:** Can be "event" (recommended) or "poll". 
  * "event" mode uses system hooks to detect changes instantly, while "poll" mode checks at regular intervals from the `delay_seconds` value.
* overrides: This is your list of target applications and their specific profiles.
    * The key is the keyword to search for (case-insensitive). This can be part of a process name or window title. 
    * The value is the specific profile to apply (e.g., "-Profile4"). If you leave the value as an empty string (""), the default profile_on will be used for that target.
## Usage
1. Configure your config.json file with your desired settings and targets.
2. Run the compiled .exe file.
3. The application will request administrator privileges (if not already elevated) and start monitoring in the background.
For best results, add the executable to your Windows startup folder so it runs automatically when you log in.
