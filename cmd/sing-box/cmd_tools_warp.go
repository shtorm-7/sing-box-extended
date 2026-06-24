package main

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var commandToolsWarp = &cobra.Command{
	Use:   "warp",
	Short: "Manage WARP/MASQUE accounts",
}

func init() {
	commandTools.AddCommand(commandToolsWarp)
}

// collectWarpEntries maps each WARP/MASQUE outbound/endpoint tag declared in the
// configuration to its type (C.TypeWARP or C.TypeMASQUE).
func collectWarpEntries(options *option.Options) map[string]string {
	entries := make(map[string]string)
	for _, outbound := range options.Outbounds {
		if outbound.Type == C.TypeMASQUE {
			entries[outbound.Tag] = outbound.Type
		}
	}
	for _, endpoint := range options.Endpoints {
		if endpoint.Type == C.TypeWARP {
			entries[endpoint.Tag] = endpoint.Type
		}
	}
	return entries
}

// selectWarpEntries resolves the WARP/MASQUE entries to operate on: all of them
// when no tags are given, otherwise the requested subset. It errors if the
// configuration declares no WARP/MASQUE outbounds, or if any requested tag is
// unknown. Shared by the warp subcommands.
func selectWarpEntries(options *option.Options, tags []string) (map[string]string, error) {
	entries := collectWarpEntries(options)
	if len(entries) == 0 {
		return nil, E.New("configuration contains no WARP or MASQUE outbounds")
	}
	if len(tags) == 0 {
		return entries, nil
	}
	selected := make(map[string]string, len(tags))
	var notFound []string
	for _, tag := range tags {
		typ, ok := entries[tag]
		if !ok {
			notFound = append(notFound, tag)
			continue
		}
		selected[tag] = typ
	}
	if len(notFound) > 0 {
		return nil, warpTagsNotFoundError(common.Uniq(notFound))
	}
	return selected, nil
}

// loadWarpProfiles returns the profile stored in the cache for each entry. It
// errors when any entry has no profile generated yet. Shared by the warp subcommands.
func loadWarpProfiles(cacheFile adapter.CacheFile, entries map[string]string) (map[string]*adapter.SavedBinary, error) {
	stored := make(map[string]*adapter.SavedBinary, len(entries))
	var notStored []string
	for tag, typ := range entries {
		var saved *adapter.SavedBinary
		switch typ {
		case C.TypeMASQUE:
			saved = cacheFile.LoadMASQUEConfig(tag)
		case C.TypeWARP:
			saved = cacheFile.LoadWARPConfig(tag)
		}
		if saved == nil {
			notStored = append(notStored, tag)
			continue
		}
		stored[tag] = saved
	}
	if len(notStored) > 0 {
		return nil, warpTagsNotGeneratedError(notStored)
	}
	return stored, nil
}

// warpTagsNotFoundError lists requested tags that are not WARP/MASQUE outbounds.
type warpTagsNotFoundError []string

func (e warpTagsNotFoundError) Error() string {
	return "no WARP/MASQUE endpoint/outbound with tags: " + strings.Join(e, ", ")
}

// warpTagsNotGeneratedError lists WARP/MASQUE tags that have no stored profile yet.
type warpTagsNotGeneratedError []string

func (e warpTagsNotGeneratedError) Error() string {
	return "no stored profile for tags: " + strings.Join(e, ", ")
}
