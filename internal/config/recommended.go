package config

const (
	ConfigurationAutomatic = "automatic"
	ConfigurationManual    = "manual"
)

// ApplyRecommended enables embedded FRP without client FRP TLS for simple
// deployment. All other settings, permissions, credentials and PKI stay intact.
func ApplyRecommended(cfg *Config) {
	cfg.EmbeddedFRPEnabled = true
	cfg.FRPTransportTLS = false
}
