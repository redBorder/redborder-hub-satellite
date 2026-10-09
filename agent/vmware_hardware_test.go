package agent

import "testing"

const sampleVMInfo = `{"virtualMachines":[{
  "self":{"value":"vm-12"},
  "runtime":{"powerState":"poweredOn"},
  "config":{"name":"web01","uuid":"422f-aa","guestFullName":"Ubuntu Linux (64-bit)",
    "hardware":{"numCPU":2,"memoryMB":4096,"device":[
      {"key":2000,"deviceInfo":{"label":"Hard disk 1","summary":"40,960 KB"},
       "capacityInKB":41943040,"backing":{"fileName":"[ds1] web01/web01.vmdk"}},
      {"key":2001,"deviceInfo":{"label":"Hard disk 2"},"capacityInKB":1048576,
       "backing":{"fileName":"[ds1] web01/web01.vmdk"}},
      {"key":4000,"deviceInfo":{"label":"Network adapter 1","summary":"VLAN_1"},
       "macAddress":"00:50:56:aa:bb:cc","backing":{"deviceName":"VLAN_1"},
       "connectable":{"connected":false}}
    ]}},
  "guest":{"ipAddress":"10.0.0.5","net":[
    {"deviceConfigId":4000,"macAddress":"00:50:56:AA:BB:CC","ipAddress":["10.0.0.5"],
     "ipConfig":{"ipAddress":[{"ipAddress":"10.0.0.5","prefixLength":24}]}}]}
}]}`

func TestParseVMwareHardware(t *testing.T) {
	hw, err := parseVMwareHardware([]byte(sampleVMInfo), "web01")
	if err != nil || hw == nil {
		t.Fatalf("expected hardware, got %v / %v", hw, err)
	}
	if hw.Name != "web01" || hw.UUID != "422f-aa" || hw.PowerState != "poweredOn" {
		t.Errorf("unexpected identity: %+v", hw)
	}
	if hw.VCPUs != 2 || hw.MemoryMB != 4096 || hw.GuestOS != "Ubuntu Linux (64-bit)" {
		t.Errorf("unexpected resources: %+v", hw)
	}
	if len(hw.Disks) != 2 || hw.Disks[0].SizeMB != 40960 || hw.Disks[0].Datastore != "ds1" {
		t.Fatalf("unexpected disks: %+v", hw.Disks)
	}
	if hw.Disks[0].Name != "web01.vmdk" || hw.Disks[1].Name != "web01.vmdk-2" {
		t.Errorf("duplicate disk names not disambiguated: %+v", hw.Disks)
	}
	if len(hw.Interfaces) != 1 {
		t.Fatalf("unexpected interfaces: %+v", hw.Interfaces)
	}
	nic := hw.Interfaces[0]
	if nic.Connected || nic.NetworkName != "VLAN_1" || nic.MACAddress != "00:50:56:aa:bb:cc" {
		t.Errorf("unexpected nic: %+v", nic)
	}
	if len(nic.IPAddresses) != 1 || nic.IPAddresses[0].Address != "10.0.0.5" ||
		nic.IPAddresses[0].PrefixLength == nil || *nic.IPAddresses[0].PrefixLength != 24 {
		t.Errorf("unexpected ips: %+v", nic.IPAddresses)
	}
}

func TestParseVMwareHardwareCapitalizedKeys(t *testing.T) {
	hw, _ := parseVMwareHardware([]byte(`{"VirtualMachines":[{"Config":{"Name":"x","Uuid":"u"},"Runtime":{"PowerState":"poweredOff"}}]}`), "")
	if hw == nil || hw.Name != "x" || hw.UUID != "u" || hw.PowerState != "poweredOff" {
		t.Errorf("unexpected hardware: %+v", hw)
	}
}

func TestParseVMwareHardwareNotFound(t *testing.T) {
	for _, in := range []string{"", "not json", `{"virtualMachines":[]}`, `{}`} {
		if hw, err := parseVMwareHardware([]byte(in), "x"); hw != nil || err != nil {
			t.Errorf("input %q: expected nil, got %v / %v", in, hw, err)
		}
	}
}
