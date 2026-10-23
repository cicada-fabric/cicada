package hubtransport

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestContractInventoryAndFrozenActivation(t *testing.T) {
	raw, err := os.ReadFile("contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Revision         string   `json:"contract_revision"`
		Version          int      `json:"version"`
		DescriptorFormat string   `json:"descriptor_format"`
		DescriptorPrefix string   `json:"descriptor_prefix"`
		BootstrapFormat  string   `json:"bootstrap_format"`
		BootstrapPrefix  string   `json:"bootstrap_prefix"`
		ClaimsFields     []string `json:"claims_fields"`
		DescriptorFields []string `json:"descriptor_fields"`
		BootstrapFields  []string `json:"bootstrap_fields"`
		MaxDescriptor    int      `json:"max_descriptor_bytes"`
		MaxBootstrap     int      `json:"max_bootstrap_bytes"`
		MaxRoot          int      `json:"max_root_certificate_bytes"`
		Activation       string   `json:"existing_activation_format"`
		SkipVerify       bool     `json:"insecure_skip_verify"`
		Authority        bool     `json:"descriptor_grants_authority"`
		Preserve         bool     `json:"activation_code_preserved_exact"`
	}
	if json.Unmarshal(raw, &c) != nil {
		t.Fatal("invalid contract JSON")
	}
	if c.Revision != "hub-native-tls-v1" || c.Version != Version || c.DescriptorFormat != DescriptorFormat || c.DescriptorPrefix != DescriptorPrefix || c.BootstrapFormat != BootstrapFormat || c.BootstrapPrefix != BootstrapPrefix ||
		c.MaxDescriptor != MaxDescriptorBytes || c.MaxBootstrap != MaxBootstrapBytes || c.MaxRoot != MaxRootCertificateBytes || c.Activation != wire.ActivationFormat || c.SkipVerify || c.Authority || !c.Preserve {
		t.Fatal("contract drift")
	}
	for _, row := range []struct {
		value  any
		fields []string
	}{{Claims{}, c.ClaimsFields}, {Descriptor{}, c.DescriptorFields}, {Bootstrap{}, c.BootstrapFields}} {
		typ := reflect.TypeOf(row.value)
		fields := make([]string, typ.NumField())
		for i := range fields {
			fields[i] = typ.Field(i).Tag.Get("json")
		}
		if !reflect.DeepEqual(fields, row.fields) {
			t.Fatal("public DTO fields differ from contract")
		}
	}
}
