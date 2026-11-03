package core

// The standard formats the SDK reads are the CTIS interoperability adapters
// (github.com/openctemio/ctis/v2/interop/<format>), separate modules since
// CTIS 2.0. Each registers its formats with the ctis importer when imported,
// so importer.Parse reads SARIF, CycloneDX, SPDX, CSAF and OpenVEX wherever
// this package is linked: the SARIF parser here, the tool host's named
// formats and the file import tool.
import (
	_ "github.com/openctemio/ctis/v2/interop/csaf"
	_ "github.com/openctemio/ctis/v2/interop/cyclonedx"
	_ "github.com/openctemio/ctis/v2/interop/openvex"
	_ "github.com/openctemio/ctis/v2/interop/sarif"
	_ "github.com/openctemio/ctis/v2/interop/spdx"
)
