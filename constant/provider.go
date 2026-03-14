package constant

const (
	ProviderTypeInline = "inline"
	ProviderTypeLocal  = "local"
	ProviderTypeRemote = "remote"
)

func ProviderDisplayName(providerType string) string {
	switch providerType {
	case ProviderTypeInline:
		return "Inline"
	case ProviderTypeLocal:
		return "Local"
	case ProviderTypeRemote:
		return "Remote"
	default:
		return "Unknown"
	}
}
