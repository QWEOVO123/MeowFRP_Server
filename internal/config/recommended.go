package config

const (
	ConfigurationAutomatic = "automatic"
	ConfigurationManual    = "manual"
)

// Fresh installations default to TLS. Preserve explicitly saved TLS choices,
// including disabled TLS, when applying other automatic recommendations.
func ApplyRecommended(cfg *Config) {
	cfg.EmbeddedFRPEnabled = true
}
