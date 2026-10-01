package tenable

import (
	"reflect"
	"strings"
	"testing"
)

const identNessus = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="ids">
    <ReportHost name="10.0.0.7">
      <HostProperties>
        <tag name="host-ip">10.0.0.7</tag>
        <tag name="host-fqdn">db01.corp.local</tag>
        <tag name="mac-address">00:50:56:AB:CD:01
00:50:56:ab:cd:02 not-a-mac
00:50:56:ab:cd:01</tag>
        <tag name="bios-uuid">4C4C4544-0042-3510-8051-B4C04F4E4D32</tag>
        <tag name="aws-instance-instanceId">i-0abc1234def567890</tag>
      </HostProperties>
    </ReportHost>
    <ReportHost name="10.0.0.8">
      <HostProperties><tag name="host-ip">10.0.0.8</tag></HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

func TestConvert_HostIdentifiers(t *testing.T) {
	rep, err := Convert(strings.NewReader(identNessus), ConvertOptions{ToolName: "tenable"})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	ids := rep.Assets[0].Identifiers
	if ids == nil {
		t.Fatal("expected identifiers on a host with mac-address, bios-uuid and an AWS instance id")
	}
	if want := []string{"00:50:56:ab:cd:01", "00:50:56:ab:cd:02"}; !reflect.DeepEqual(ids.MACAddresses, want) {
		t.Errorf("MACAddresses = %v, want %v", ids.MACAddresses, want)
	}
	if ids.BIOSUUID != "4C4C4544-0042-3510-8051-B4C04F4E4D32" {
		t.Errorf("BIOSUUID = %q", ids.BIOSUUID)
	}
	if ids.CloudResourceID != "i-0abc1234def567890" {
		t.Errorf("CloudResourceID = %q", ids.CloudResourceID)
	}
	// Older APIs read the property; it stays.
	if rep.Assets[0].Properties["mac_address"] == nil {
		t.Error("mac_address property must be kept")
	}
	if rep.Assets[1].Identifiers != nil {
		t.Errorf("a host with no identifying tags must not get an identifiers block, got %+v", rep.Assets[1].Identifiers)
	}
}
