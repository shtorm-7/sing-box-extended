package main

import (
	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"github.com/spf13/cobra"
)

var commandToolsWarpGenForce bool

var commandToolsWarpGen = &cobra.Command{
	Use:   "gen [tags...]",
	Short: "Generate WARP/MASQUE account profiles into the cache",
	Run: func(cmd *cobra.Command, args []string) {
		err := warpGen(args, commandToolsWarpGenForce)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandToolsWarpGen.Flags().BoolVar(&commandToolsWarpGenForce, "force", false, "regenerate even if a profile is already stored")
	commandToolsWarp.AddCommand(commandToolsWarpGen)
}

func warpGen(tags []string, force bool) error {
	options, err := readConfigAndMerge()
	if err != nil {
		return err
	}
	entries, err := selectWarpEntries(&options, tags)
	if err != nil {
		return err
	}
	if options.Experimental == nil || options.Experimental.CacheFile == nil || !options.Experimental.CacheFile.Enabled {
		return E.New("cache_file is not enabled in configuration")
	}
	// Without the matching store flag the generated profile is never persisted, so
	// generation would be a no-op.
	cacheFile := options.Experimental.CacheFile
	for _, typ := range entries {
		var stored bool
		switch typ {
		case C.TypeWARP:
			stored = cacheFile.StoreWARPConfig
		case C.TypeMASQUE:
			stored = cacheFile.StoreMASQUEConfig
		}
		if !stored {
			return E.New(`generating without storing makes no sense (`, typ, `)`)
		}
	}

	instance, cancel, err := createPreStartedClient()
	if err != nil {
		return err
	}
	defer func() {
		cancel()
		instance.Close()
	}()

	// With -o the registration request is routed through that outbound; otherwise
	// the configured profile detour (if any) is used.
	var dialer N.Dialer
	if commandToolsFlagOutbound != "" {
		dialer, err = createDialer(instance, commandToolsFlagOutbound)
		if err != nil {
			return err
		}
	}

	// GenerateConfig keeps an already-stored profile unless force is set, matching
	// the behavior of a normal start.
	for tag, typ := range entries {
		generator, ok := warpGeneratorByTag(instance, tag, typ)
		if !ok {
			return E.New("no generator for tag: ", tag)
		}
		if err := generator.GenerateConfig(force, dialer); err != nil {
			return E.Cause(err, "generate ", tag)
		}
	}
	return nil
}

type warpConfigGenerator interface {
	GenerateConfig(recreate bool, dialer N.Dialer) error
}

func warpGeneratorByTag(instance *box.Box, tag, typ string) (warpConfigGenerator, bool) {
	switch typ {
	case C.TypeMASQUE:
		if outbound, loaded := instance.Outbound().Outbound(tag); loaded {
			generator, ok := outbound.(warpConfigGenerator)
			return generator, ok
		}
	case C.TypeWARP:
		if endpoint, loaded := instance.Endpoint().Get(tag); loaded {
			generator, ok := endpoint.(warpConfigGenerator)
			return generator, ok
		}
	}
	return nil, false
}
