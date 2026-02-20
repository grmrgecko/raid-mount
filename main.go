package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/term"
)

// RaidMount holds mount point details parsed from the raid table.
type RaidMount struct {
	Source    string
	Target   string
	FSType   string
	Flags    string
	CryptName string
	Encrypted bool
	Parallel  bool
}

// App is the global application structure.
type App struct {
	flags  *Flags
	config Config
}

var app *App

// isMounted checks /proc/mounts for a target mountpoint to determine if it is mounted.
func isMounted(target string) bool {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		args := strings.Fields(scanner.Text())
		if len(args) < 3 {
			continue
		}
		if args[1] == target {
			return true
		}
	}
	return false
}

// closeLUKS attempts to close a LUKS volume by name, logging any failure.
func closeLUKS(cryptName string) {
	cmd := exec.Command("cryptsetup", "close", cryptName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to close LUKS volume %s: %v\n", cryptName, err)
	}
}

// mountBindfs handles mounting a bindfs FUSE filesystem.
//
// The Flags field uses a "|" separator to distinguish bindfs native flags from
// FUSE -o options:
//
//	"resolve-symlinks|allow_other"
//	 └─ passed as --resolve-symlinks    └─ passed as -o allow_other
//
// Either side of the "|" may be empty. If no "|" is present the entire Flags
// string is treated as bindfs native flags with no -o options.
func mountBindfs(mount RaidMount) error {
	if isMounted(mount.Target) {
		fmt.Println(mount.Target, "is already mounted")
		return nil
	}

	// Split flags into bindfs native flags and FUSE -o options.
	var bindfsFlags []string
	var fuseOpts string

	parts := strings.SplitN(mount.Flags, "|", 2)
	nativeRaw := strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		fuseOpts = strings.TrimSpace(parts[1])
	}

	// Each comma-separated native flag becomes a --flag argument.
	if nativeRaw != "" {
		for _, f := range strings.Split(nativeRaw, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				bindfsFlags = append(bindfsFlags, "--"+f)
			}
		}
	}

	// Build the full argument list.
	args := bindfsFlags
	if fuseOpts != "" {
		args = append(args, "-o", fuseOpts)
	}
	args = append(args, mount.Source, mount.Target)

	fmt.Println("bindfs", args)
	cmd := exec.Command("bindfs", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bindfs %s: %w", mount.Target, err)
	}

	if !isMounted(mount.Target) {
		return fmt.Errorf("unable to mount: %s", mount.Target)
	}
	return nil
}

// mountDrive decrypts (if needed) and mounts a single drive. Returns an error
// instead of calling log.Fatal so the caller can coordinate shutdown safely.
func mountDrive(mount RaidMount, encryptionPassword string) error {
	// Dispatch bindfs mounts to their own handler. bindfs mounts are never
	// encrypted so we skip the cryptsetup path entirely.
	if mount.FSType == "bindfs" {
		return mountBindfs(mount)
	}

	// Track whether we opened the LUKS volume ourselves so we can clean up on failure.
	openedLUKS := false

	// If encrypted, decrypt the drive.
	if mount.Encrypted {
		// Check the device path to see if the encrypted drive is already decrypted.
		dmPath := "/dev/mapper/" + mount.CryptName
		if _, err := os.Stat(dmPath); err == nil {
			fmt.Println("Already decrypted:", mount.CryptName)
		} else {
			// Decrypt the drive.
			args := []string{
				"open",
				mount.Source,
				mount.CryptName,
			}

			// If encryption key file was provided, add argument.
			if app.config.EncryptionKey != "" {
				args = append(args, "--key-file="+app.config.EncryptionKey)
			}

			fmt.Println("cryptsetup", args)
			cmd := exec.Command("cryptsetup", args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			stdin, err := cmd.StdinPipe()
			if err != nil {
				return fmt.Errorf("cryptsetup stdin pipe for %s: %w", mount.CryptName, err)
			}

			if err := cmd.Start(); err != nil {
				return fmt.Errorf("cryptsetup start %s: %w", mount.CryptName, err)
			}

			// If password was provided, send it to cryptsetup and close stdin
			// so the process receives EOF and does not block.
			if encryptionPassword != "" {
				fmt.Fprintln(stdin, encryptionPassword)
			}
			stdin.Close()

			if err := cmd.Wait(); err != nil {
				return fmt.Errorf("cryptsetup open %s: %w", mount.CryptName, err)
			}

			// If we cannot verify that it is decrypted, the mount will not work.
			if _, err := os.Stat(dmPath); err != nil {
				return fmt.Errorf("unable to decrypt: %s", mount.CryptName)
			}
			openedLUKS = true
		}

		// Now that it is decrypted, update the source path for mounting.
		mount.Source = dmPath
	}

	// If we're already mounted on this mountpoint, skip.
	if isMounted(mount.Target) {
		fmt.Println(mount.Target, "is already mounted")
		return nil
	}

	// Build mount arguments, only adding -o if flags are non-empty.
	args := []string{"-t", mount.FSType}
	if mount.Flags != "" {
		args = append(args, "-o", mount.Flags)
	}
	args = append(args, mount.Source, mount.Target)

	fmt.Println("mount", args)
	cmd := exec.Command("mount", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if mount.Encrypted && openedLUKS {
			closeLUKS(mount.CryptName)
		}
		return fmt.Errorf("mount %s: %w", mount.Target, err)
	}

	// Verify that it actually mounted.
	if !isMounted(mount.Target) {
		if mount.Encrypted && openedLUKS {
			closeLUKS(mount.CryptName)
		}
		return fmt.Errorf("unable to mount: %s", mount.Target)
	}
	return nil
}

// main is the entry point for the application.
func main() {
	// Only allow running as root.
	if os.Getuid() != 0 {
		fmt.Println("You must call this program as root.")
		os.Exit(1)
	}

	// Read configurations.
	app = new(App)
	app.flags = new(Flags)
	app.flags.Init()
	app.ReadConfig()

	// The raid table is how we know what to mount, and it must exist to start.
	if _, err := os.Stat(app.config.RaidTablePath); err != nil {
		log.Fatalln("Raid table does not exist.")
	}

	var raidMounts []RaidMount
	hasEncryptedDrives := false

	// Open the raid mountpoint table file.
	raidTab, err := os.Open(app.config.RaidTablePath)
	if err != nil {
		log.Fatalln("Unable to open raid table:", err)
	}

	// Prepare scanners and regular expressions for parsing raid table.
	scanner := bufio.NewScanner(raidTab)
	comment := regexp.MustCompile(`#.*`)
	uuidMatch := regexp.MustCompile(`^UUID=["]*([0-9a-f-]+)["]*$`)
	partuuidMatch := regexp.MustCompile(`^PARTUUID=["]*([0-9a-f-]+)["]*$`)

	// Each line item, parse the mountpoint.
	for scanner.Scan() {
		// Read line, and clean up comments/parse fields.
		line := scanner.Text()
		line = comment.ReplaceAllString(line, "")
		args := strings.Fields(line)

		// If line contains no fields, we can ignore it.
		if len(args) == 0 {
			continue
		}

		// If line is not 6 fields, some formatting is wrong in the table.
		if len(args) != 6 {
			log.Println("Line does not have correct number of arguments:", line)
			continue
		}

		// Put fields into mountpoint structure.
		mount := RaidMount{
			Source:    strings.ReplaceAll(args[0], "\\040", " "),
			Target:    strings.ReplaceAll(args[1], "\\040", " "),
			FSType:    args[2],
			Flags:     args[3],
			CryptName: args[4],
			Encrypted: false,
			Parallel:  false,
		}

		// If the CryptName field is not none, then it is an encrypted drive.
		if mount.CryptName != "none" {
			mount.Encrypted = true
			hasEncryptedDrives = true
		}

		// Determine if parallel mount.
		if args[5] == "1" {
			mount.Parallel = true
		}

		// If the source drive is a UUID or PARTUUID, expand to device name.
		if uuidMatch.MatchString(mount.Source) {
			uuid := uuidMatch.FindStringSubmatch(mount.Source)
			mount.Source = "/dev/disk/by-uuid/" + uuid[1]
		} else if partuuidMatch.MatchString(mount.Source) {
			uuid := partuuidMatch.FindStringSubmatch(mount.Source)
			mount.Source = "/dev/disk/by-partuuid/" + uuid[1]
		}

		raidMounts = append(raidMounts, mount)
	}
	raidTab.Close()

	// If the encryption key was passed as a flag, override the configuration file.
	if app.flags.EncryptionKey != "" {
		app.config.EncryptionKey = app.flags.EncryptionKey
	}

	// If the encryption key file is set, we need to verify it actually exists.
	if app.config.EncryptionKey != "" {
		if _, err := os.Stat(app.config.EncryptionKey); err != nil {
			log.Fatalln("Encryption key specified does not exist.")
		}
	}

	// Resolve the encryption password from flag, environment variable, or interactive prompt.
	encryptionPassword := app.flags.EncryptionPassword
	if encryptionPassword == "" {
		encryptionPassword = os.Getenv("RAID_MOUNT_ENCRYPTION_PASSWORD")
	}
	if encryptionPassword == "" && app.config.EncryptionKey == "" && hasEncryptedDrives {
		fmt.Print("Please enter the encryption password: ")

		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalln("Unable to read password:", err)
		}
		fmt.Println()

		encryptionPassword = string(bytePassword)
	}

	// With each mountpoint, decrypt and mount. Errors are collected so that a
	// single failure does not silently kill goroutines via os.Exit.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var mountErrors []error

	for _, mount := range raidMounts {
		// A non-parallel entry acts as a barrier: wait for all prior mounts to
		// complete and abort if any of them failed.
		if !mount.Parallel {
			wg.Wait()
			mu.Lock()
			if len(mountErrors) > 0 {
				for _, e := range mountErrors {
					log.Println(e)
				}
				log.Fatalln("Aborting due to mount errors.")
			}
			mu.Unlock()
		}

		wg.Add(1)
		go func(m RaidMount) {
			defer wg.Done()
			if err := mountDrive(m, encryptionPassword); err != nil {
				mu.Lock()
				mountErrors = append(mountErrors, err)
				mu.Unlock()
			}
		}(mount)
	}

	// Wait for all remaining mounts and check for errors before starting services.
	wg.Wait()
	if len(mountErrors) > 0 {
		for _, e := range mountErrors {
			log.Println(e)
		}
		log.Fatalln("Aborting due to mount errors.")
	}

	// Now that all mountpoints are mounted, start the configured services.
	for _, service := range app.config.Services {
		args := []string{"start", service}

		fmt.Println("systemctl", args)
		cmd := exec.Command("systemctl", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			log.Println("Failed to start service", service+":", err)
		}
	}
}
