// Package sensorstate keeps an API-key sensor's state: the state directory,
// the credentials file in it (the renewed API key, written atomically and
// 0600), the choice between the configured and the renewed key at start, and
// the key renewal loop with its protocol v2 client (POST /api/v2/sensor/keys).
//
// It holds what sensorkit used from the former pkg/platform, whose
// registration, lease and poll routes no OpenCTEM API served; that package
// is removed.
package sensorstate
