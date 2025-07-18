package watcher

import (
	"log"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
)

// WinEvent constants for event-driven watching
const (
	eventSystemForeground = 0x0003
	eventObjectCreate     = 0x8000
	eventObjectDestroy    = 0x8001
	wndOutofcontext       = 0x0000
)

// Lazy-load necessary DLL procedures for performance.
var (
	user32                       = windows.NewLazySystemDLL("user32.dll")
	procGetForegroundWindow      = user32.NewProc("GetForegroundWindow")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procGetWindowTextW           = user32.NewProc("GetWindowTextW")
	procGetWindowTextLen         = user32.NewProc("GetWindowTextLengthW")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procSetWinEventHook          = user32.NewProc("SetWinEventHook")
	procUnhookWinEvent           = user32.NewProc("UnhookWinEvent")
	procGetMessageW              = user32.NewProc("GetMessageW")
	procTranslateMessage         = user32.NewProc("TranslateMessage")
	procDispatchMessageW         = user32.NewProc("DispatchMessageW")

	kernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procOpenProcess = kernel32.NewProc("OpenProcess")
	procCloseHandle = kernel32.NewProc("CloseHandle")

	psapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetModuleFileNameExW = psapi.NewProc("GetModuleFileNameExW")
)

// StartEventWatcher sets up Windows event hooks to listen for system events.
func StartEventWatcher(handler func()) {
	go func() {
		winEventProc := syscall.NewCallback(func(hWinEventHook syscall.Handle, event uint32, hwnd syscall.Handle, idObject int32, idChild int32, idEventThread uint32, dwmsEventTime uint32) uintptr {
			handler()
			return 0
		})

		hookForeground, _, err := procSetWinEventHook.Call(eventSystemForeground, eventSystemForeground, 0, winEventProc, 0, 0, wndOutofcontext)
		if hookForeground == 0 {
			log.Fatalf("Fatal: Could not set foreground event hook: %v", err)
		}
		hookCreate, _, err := procSetWinEventHook.Call(eventObjectCreate, eventObjectDestroy, 0, winEventProc, 0, 0, wndOutofcontext)
		if hookCreate == 0 {
			log.Fatalf("Fatal: Could not set create/destroy event hook: %v", err)
		}

		defer func() {
			ret, _, err := procUnhookWinEvent.Call(hookForeground)
			if ret == 0 {
				log.Printf("Warning: Failed to unhook foreground event hook: %v", err)
			}
		}()
		defer func() {
			ret, _, err := procUnhookWinEvent.Call(hookCreate)
			if ret == 0 {
				log.Printf("Warning: Failed to unhook create/destroy event hook: %v", err)
			}
		}()

		// log.Println("Event hooks set. Listening for system events...")

		var msg struct{ Hwnd, Message, WParam, LParam, Time, Pt uintptr }
		for {
			ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if int32(ret) == -1 {
				break
			}
			_, _, err := procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			if err != nil && err.(syscall.Errno) != 0 {
				log.Fatalf("TranslateMessage failed: %v", err)
			}
			_, _, err = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
			if err != nil && err.(syscall.Errno) != 0 {
				log.Fatalf("DispatchMessageW failed: %v", err)
			}

		}
	}()
}

// FirstActiveTarget checks for a target using partial matching, prioritizing the foreground application.
// It returns the *keyword* that was matched, and a boolean indicating if a match was found.
func FirstActiveTarget(targets map[string]string) (string, bool) {
	keywords := make([]string, 0, len(targets))
	for k := range targets {
		keywords = append(keywords, k)
	}

	if name, ok := getForegroundTarget(keywords); ok {
		return name, true
	}
	if name, ok := isProcessActive(keywords); ok {
		return name, true
	}
	if name, ok := isWindowActive(keywords); ok {
		return name, true
	}
	return "", false
}

// getForegroundTarget checks if the foreground app's process or title contains a keyword.
func getForegroundTarget(keywords []string) (string, bool) {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return "", false
	}

	title := getWindowText(windows.HWND(hwnd))
	if title != "" {
		lowerTitle := strings.ToLower(title)
		for _, keyword := range keywords {
			if strings.Contains(lowerTitle, keyword) {
				return keyword, true
			}
		}
	}

	var pid uint32
	_, _, err := procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if err != nil {
		return "", false
	}
	if pid == 0 {
		return "", false
	}
	handle, _, _ := procOpenProcess.Call(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, 0, uintptr(pid))
	if handle == 0 {
		return "", false
	}
	defer func() {
		ret, _, err := procCloseHandle.Call(handle)
		if ret == 0 {
			log.Printf("Warning: Failed to close process handle %v: %v", handle, err)
		}
	}()

	buf := make([]uint16, windows.MAX_PATH)
	n, _, _ := procGetModuleFileNameExW.Call(handle, 0, uintptr(unsafe.Pointer(&buf[0])), windows.MAX_PATH)
	if n > 0 {
		exePath := windows.UTF16ToString(buf)
		lowerExeName := strings.ToLower(filepath.Base(exePath))
		for _, keyword := range keywords {
			if strings.Contains(lowerExeName, keyword) {
				return keyword, true
			}
		}
	}

	return "", false
}

// isProcessActive checks if any running process name contains a keyword.
func isProcessActive(keywords []string) (string, bool) {
	processes, err := ps.Processes()
	if err != nil {
		return "", false
	}
	for _, p := range processes {
		lowerExeName := strings.ToLower(p.Executable())
		for _, keyword := range keywords {
			if strings.Contains(lowerExeName, keyword) {
				return keyword, true
			}
		}
	}
	return "", false
}

// isWindowActive checks if any visible window title contains a keyword.
func isWindowActive(keywords []string) (string, bool) {
	var foundKeyword string
	cb := syscall.NewCallback(func(hwnd syscall.Handle, _ uintptr) uintptr {
		isVisible, _, _ := procIsWindowVisible.Call(uintptr(hwnd))
		if isVisible == 0 {
			return 1 // Continue
		}
		title := getWindowText(windows.HWND(hwnd))
		if title != "" {
			lowerTitle := strings.ToLower(title)
			for _, keyword := range keywords {
				if strings.Contains(lowerTitle, keyword) {
					foundKeyword = keyword
					return 0 // Stop enumeration
				}
			}
		}
		return 1 // Continue
	})

	// A return of 0 here can mean the callback stopped it, which is not an error.
	// A true failure is when ret is 0 AND the error is not nil.
	ret, _, err := procEnumWindows.Call(cb, 0)
	if ret == 0 && err != nil {
		log.Printf("Warning: EnumWindows call failed with an error: %v", err)
	}

	if foundKeyword != "" {
		return foundKeyword, true
	}
	return "", false
}

func getWindowText(hwnd windows.HWND) string {
	length, _, _ := procGetWindowTextLen.Call(uintptr(hwnd))
	if length == 0 {
		return ""
	}
	buf := make([]uint16, length+1)
	ret, _, _ := procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), length+1)
	if ret == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}
