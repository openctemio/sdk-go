// Package sdk identifies this SDK: its name and release version.
//
// Stability: Stable (docs/STABILITY.md).
package sdk

// Name is the SDK's product name, as sensors report it to the platform
// (heartbeat "sdk.name") and in the User-Agent.
const Name = "openctem-sdk-go"

// Version is the SDK release this source tree is, without a leading "v".
//
// The version a sensor reports is read from the binary's build info
// (useragent.SDKVersion), which a release tag sets by itself: a sensor built
// against github.com/openctemio/sdk-go@v0.10.0 reports "0.10.0" whatever this
// constant says. Version is only the fallback for a binary without build
// info, and the base of "<Version>-devel" for a build from a local checkout
// (a replace directive, go run in this repository).
//
// A release PR sets it to the version being tagged; TestVersionNotBehindChangelog
// fails when it is older than the newest release in CHANGELOG.md.
const Version = "0.18.0"
