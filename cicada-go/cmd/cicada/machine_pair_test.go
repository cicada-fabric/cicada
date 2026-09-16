package main

import "testing"

func TestValidatePairInput(t *testing.T) {
	valid := []struct {
		host string
		user string
		port int
		id   string
	}{
		{host: "gpu2.example", user: "runner", port: 22, id: "gpu2"},
		{host: "cluster-alias", port: 2222, id: "cluster"},
	}
	for _, test := range valid {
		if err := validatePairInput(test.host, test.user, test.port, test.id); err != nil {
			t.Errorf("valid pairing input rejected: %#v: %v", test, err)
		}
	}
	invalid := []struct {
		host string
		user string
		port int
		id   string
	}{
		{host: "", port: 22, id: "gpu2"},
		{host: "-oProxyCommand=bad", port: 22, id: "gpu2"},
		{host: "gpu 2", port: 22, id: "gpu2"},
		{host: "gpu2", user: "runner@other", port: 22, id: "gpu2"},
		{host: "gpu2", port: 0, id: "gpu2"},
		{host: "gpu2", port: 22, id: ""},
	}
	for _, test := range invalid {
		if err := validatePairInput(test.host, test.user, test.port, test.id); err == nil {
			t.Errorf("invalid pairing input was accepted: %#v", test)
		}
	}
}

func TestBoundedOutputCapsRemoteDiscovery(t *testing.T) {
	var output boundedOutput
	data := make([]byte, machineDiscoveryOutputLimit+100)
	if written, err := output.Write(data); err != nil || written != len(data) {
		t.Fatalf("bounded output write: written=%d err=%v", written, err)
	}
	if output.Len() != machineDiscoveryOutputLimit || !output.limited {
		t.Fatalf("remote output was not capped: len=%d limited=%v", output.Len(), output.limited)
	}
}
