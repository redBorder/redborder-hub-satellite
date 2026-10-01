package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"redborder-hub-satellite/common"
)

var (
	vmwareSizeKBRegex = regexp.MustCompile(`(?i)([\d,]+)\s*KB`)
	vmwareSizeMBRegex = regexp.MustCompile(`(?i)([\d,]+)\s*MB`)
	vmwareSizeGBRegex = regexp.MustCompile(`(?i)([\d,]+(?:\.\d+)?)\s*GB`)
	vmwareDatastoreRe = regexp.MustCompile(`^\[(.*?)\]`)
)

func executeVMwareHardware(ctx context.Context, rawParams json.RawMessage) (interface{}, error) {
	var params common.VMwareHardwareParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return nil, fmt.Errorf("failed to parse params: %w", err)
	}

	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	result, err := runVMwareHardwareCommand(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("vmware hardware query failed: %w", err)
	}
	return result, nil
}

func runVMwareHardwareCommand(ctx context.Context, params common.VMwareHardwareParams) (*common.VMwareHardwareResult, error) {
	govcPath, err := exec.LookPath("govc")
	if err != nil {
		govcPath = "/usr/bin/govc"
		if _, statErr := os.Stat(govcPath); statErr != nil {
			return nil, errors.New("govc command not found in PATH or /usr/bin/govc")
		}
	}

	tmpHome, err := os.MkdirTemp("", fmt.Sprintf("govc-satellite-%d-*", os.Getuid()))
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary govc home: %w", err)
	}
	defer os.RemoveAll(tmpHome)

	env := append(os.Environ(),
		fmt.Sprintf("GOVC_URL=https://%s/sdk", params.Host),
		fmt.Sprintf("GOVC_USERNAME=%s", params.Username),
		fmt.Sprintf("GOVC_PASSWORD=%s", params.Password),
		"GOVC_INSECURE=true",
		"GOVC_PERSIST_SESSION=false",
		fmt.Sprintf("GOVC_HOME=%s", tmpHome),
		fmt.Sprintf("HOME=%s", tmpHome),
	)

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(params.Timeout)*time.Second)
	defer cancel()

	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(timeoutCtx, govcPath, args...)
		cmd.Env = env
		out, runErr := cmd.CombinedOutput()
		if runErr != nil {
			return nil, fmt.Errorf("govc %s failed (%v): %s", args[0], runErr, strings.TrimSpace(string(out)))
		}
		return out, nil
	}

	result := &common.VMwareHardwareResult{Host: params.Host}

	var infoOut []byte
	if params.UUID != "" {
		infoOut, err = run("vm.info", "-json", "-vm.uuid", params.UUID)
	} else {
		target := params.VMName
		if !strings.HasPrefix(target, "vm-") && !strings.HasPrefix(target, "VirtualMachine:") {
			found, findErr := run("find", "-i", "/", "-type", "m", "-name", target)
			if findErr != nil {
				return nil, findErr
			}
			if first := firstLine(string(found)); first != "" && first != "/" {
				target = first
			}
		}
		infoOut, err = run("vm.info", "-json", target)
	}
	if err != nil {
		return nil, err
	}

	hw, err := parseVMwareHardware(infoOut, params.VMName)
	if err != nil {
		return nil, err
	}
	if hw != nil {
		result.Found = true
		result.Hardware = hw
	}
	return result, nil
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// vmwareKey looks a key up ignoring case, since govc versions differ (PowerState/powerState).
func vmwareKey(m map[string]interface{}, key string) (interface{}, bool) {
	if m == nil {
		return nil, false
	}
	if v, ok := m[key]; ok && v != nil {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) && v != nil {
			return v, true
		}
	}
	return nil, false
}

func vmwareMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := vmwareKey(m, key); ok {
		if mm, isMap := v.(map[string]interface{}); isMap {
			return mm
		}
	}
	return nil
}

func vmwareList(m map[string]interface{}, key string) []interface{} {
	if v, ok := vmwareKey(m, key); ok {
		if l, isList := v.([]interface{}); isList {
			return l
		}
	}
	return nil
}

func vmwareStr(m map[string]interface{}, key string) string {
	v, ok := vmwareKey(m, key)
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func vmwareNum(m map[string]interface{}, key string) (float64, bool) {
	v, ok := vmwareKey(m, key)
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseSizeMB(summary string) int64 {
	if m := vmwareSizeKBRegex.FindStringSubmatch(summary); m != nil {
		f, _ := strconv.ParseFloat(strings.ReplaceAll(m[1], ",", ""), 64)
		return int64(math.Round(f / 1024.0))
	}
	if m := vmwareSizeMBRegex.FindStringSubmatch(summary); m != nil {
		i, _ := strconv.ParseInt(strings.ReplaceAll(m[1], ",", ""), 10, 64)
		return i
	}
	if m := vmwareSizeGBRegex.FindStringSubmatch(summary); m != nil {
		f, _ := strconv.ParseFloat(strings.ReplaceAll(m[1], ",", ""), 64)
		return int64(math.Round(f * 1024.0))
	}
	return 0
}

// parseVMwareHardware converts `govc vm.info -json` output for a VM into a hardware inventory.
// It returns nil (and no error) when the output holds no VM.
func parseVMwareHardware(stdout []byte, vmName string) (*common.VMwareHardware, error) {
	if len(strings.TrimSpace(string(stdout))) == 0 {
		return nil, nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(stdout, &data); err != nil {
		return nil, nil
	}

	vms := vmwareList(data, "virtualMachines")
	if len(vms) == 0 {
		return nil, nil
	}
	vm, _ := vms[0].(map[string]interface{})
	if vm == nil {
		return nil, nil
	}

	runtime := vmwareMap(vm, "runtime")
	config := vmwareMap(vm, "config")
	summary := vmwareMap(vm, "summary")
	summaryConfig := vmwareMap(summary, "config")
	summaryRuntime := vmwareMap(summary, "runtime")
	guest := vmwareMap(vm, "guest")
	hardware := vmwareMap(config, "hardware")
	if hardware == nil {
		hardware = vmwareMap(summaryConfig, "hardware")
	}

	disks := []common.VMwareDisk{}
	interfaces := []common.VMwareInterface{}

	guestNics := vmwareList(guest, "net")
	if guestNics == nil {
		guestNics = vmwareList(vmwareMap(summary, "guest"), "net")
	}

	for _, d := range vmwareList(hardware, "device") {
		dev, _ := d.(map[string]interface{})
		if dev == nil {
			continue
		}
		deviceInfo := vmwareMap(dev, "deviceInfo")
		label := vmwareStr(deviceInfo, "label")
		summaryStr := vmwareStr(deviceInfo, "summary")
		lowerLabel := strings.ToLower(label)

		capKB, hasKB := vmwareNum(dev, "capacityInKB")
		capBytes, hasBytes := vmwareNum(dev, "capacityInBytes")

		if hasKB || hasBytes || strings.Contains(lowerLabel, "hard disk") {
			var sizeMB int64
			switch {
			case hasKB && capKB > 0:
				sizeMB = int64(math.Round(capKB / 1024.0))
			case hasBytes && capBytes > 0:
				sizeMB = int64(math.Round(capBytes / (1024.0 * 1024.0)))
			default:
				sizeMB = parseSizeMB(summaryStr)
			}

			backing := vmwareMap(dev, "backing")
			fileName := firstNonEmpty(vmwareStr(backing, "fileName"), vmwareStr(backing, "diskPath"))
			datastore := ""
			vmdkBase := ""
			if fileName != "" {
				if m := vmwareDatastoreRe.FindStringSubmatch(fileName); m != nil {
					datastore = m[1]
				}
				vmdkBase = fileName
				if idx := strings.Index(vmdkBase, "]"); strings.HasPrefix(vmdkBase, "[") && idx >= 0 {
					vmdkBase = strings.TrimSpace(vmdkBase[idx+1:])
				}
				if idx := strings.LastIndex(vmdkBase, "/"); idx >= 0 {
					vmdkBase = vmdkBase[idx+1:]
				}
			}

			diskLabel := firstNonEmpty(label, fmt.Sprintf("Hard disk %d", len(disks)+1))
			baseName := firstNonEmpty(vmdkBase, diskLabel)
			diskName := baseName
			for _, existing := range disks {
				if existing.Name == diskName {
					same := 0
					for _, e := range disks {
						if e.RawName == baseName {
							same++
						}
					}
					diskName = fmt.Sprintf("%s-%d", baseName, same+1)
					break
				}
			}

			disks = append(disks, common.VMwareDisk{
				Name:        diskName,
				RawName:     baseName,
				Label:       diskLabel,
				SizeMB:      sizeMB,
				BackingFile: fileName,
				Datastore:   datastore,
				VMDKBase:    vmdkBase,
			})
		}

		mac := vmwareStr(dev, "macAddress")
		if mac != "" || strings.Contains(lowerLabel, "network adapter") || strings.Contains(lowerLabel, "ethernet") {
			connected := true
			if v, ok := vmwareKey(vmwareMap(dev, "connectable"), "connected"); ok {
				if b, isBool := v.(bool); isBool {
					connected = b
				}
			}

			backing := vmwareMap(dev, "backing")
			networkName := firstNonEmpty(vmwareStr(backing, "deviceName"), summaryStr)

			devKey := vmwareStr(dev, "key")
			var guestNic map[string]interface{}
			for _, g := range guestNics {
				gnic, _ := g.(map[string]interface{})
				if gnic == nil {
					continue
				}
				gKey := vmwareStr(gnic, "deviceConfigId")
				gMac := vmwareStr(gnic, "macAddress")
				if (devKey != "" && gKey != "" && gKey == devKey) ||
					(mac != "" && gMac != "" && strings.EqualFold(gMac, mac)) {
					guestNic = gnic
					break
				}
			}

			guestIfName := ""
			ipAddresses := []common.VMwareIPAddress{}
			if guestNic != nil {
				guestIfName = firstNonEmpty(vmwareStr(guestNic, "networkPath"),
					vmwareStr(guestNic, "deviceName"), vmwareStr(guestNic, "name"))
				if mac == "" {
					mac = vmwareStr(guestNic, "macAddress")
				}

				for _, e := range vmwareList(vmwareMap(guestNic, "ipConfig"), "ipAddress") {
					var ip string
					var prefix *int
					if entry, isMap := e.(map[string]interface{}); isMap {
						ip = vmwareStr(entry, "ipAddress")
						if p, ok := vmwareNum(entry, "prefixLength"); ok {
							pi := int(p)
							prefix = &pi
						}
					} else if s, isStr := e.(string); isStr {
						ip = strings.TrimSpace(s)
					}
					if ip != "" {
						ipAddresses = append(ipAddresses, common.VMwareIPAddress{Address: ip, PrefixLength: prefix})
					}
				}

				for _, raw := range vmwareList(guestNic, "ipAddress") {
					ip, _ := raw.(string)
					ip = strings.TrimSpace(ip)
					if ip != "" && !hasVMwareIP(ipAddresses, ip) {
						ipAddresses = append(ipAddresses, common.VMwareIPAddress{Address: ip})
					}
				}
			}

			nicLabel := firstNonEmpty(label, fmt.Sprintf("Network adapter %d", len(interfaces)+1))
			baseName := firstNonEmpty(guestIfName, networkName, nicLabel)
			nicName := baseName
			for _, existing := range interfaces {
				if existing.Name == nicName {
					same := 0
					for _, e := range interfaces {
						if e.RawName == baseName {
							same++
						}
					}
					nicName = fmt.Sprintf("%s-%d", baseName, same+1)
					break
				}
			}

			interfaces = append(interfaces, common.VMwareInterface{
				Name:        nicName,
				RawName:     baseName,
				Label:       nicLabel,
				MACAddress:  mac,
				Connected:   connected,
				NetworkName: networkName,
				GuestIfName: guestIfName,
				IPAddresses: ipAddresses,
			})
		}
	}

	// A primary guest IP that matched no interface goes to the first interface
	primaryIP := vmwareStr(guest, "ipAddress")
	if primaryIP != "" && len(interfaces) > 0 {
		matched := false
		for _, i := range interfaces {
			if hasVMwareIP(i.IPAddresses, primaryIP) {
				matched = true
				break
			}
		}
		if !matched {
			interfaces[0].IPAddresses = append(interfaces[0].IPAddresses, common.VMwareIPAddress{Address: primaryIP})
		}
	}

	vcpus, ok := vmwareNum(hardware, "numCPU")
	if !ok {
		vcpus, _ = vmwareNum(summaryConfig, "numCpu")
	}
	memMB, ok := vmwareNum(hardware, "memoryMB")
	if !ok {
		memMB, _ = vmwareNum(summaryConfig, "memorySizeMB")
	}

	return &common.VMwareHardware{
		Name:       firstNonEmpty(vmwareStr(config, "name"), vmwareStr(summaryConfig, "name"), vmName),
		PowerState: firstNonEmpty(vmwareStr(runtime, "powerState"), vmwareStr(summaryRuntime, "powerState")),
		UUID:       vmwareStr(config, "uuid"),
		GuestOS:    firstNonEmpty(vmwareStr(config, "guestFullName"), vmwareStr(guest, "guestFullName")),
		IPAddress:  primaryIP,
		VCPUs:      int64(vcpus),
		MemoryMB:   int64(memMB),
		Disks:      disks,
		Interfaces: interfaces,
	}, nil
}

func hasVMwareIP(list []common.VMwareIPAddress, ip string) bool {
	for _, e := range list {
		if e.Address == ip {
			return true
		}
	}
	return false
}
