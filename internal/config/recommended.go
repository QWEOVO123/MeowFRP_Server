package config

const (
	ConfigurationAutomatic = "automatic"
	ConfigurationManual    = "manual"
)

// Product transport is always TCP+TLS, independently of tuning mode.
func ApplyRecommended(cfg *Config) {
	cfg.EmbeddedFRPEnabled = true
	cfg.FRPTransportTLS = true
}
