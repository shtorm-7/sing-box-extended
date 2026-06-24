package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var commandToolsWarpGet = &cobra.Command{
	Use:   "get [tags...]",
	Short: "Show stored WARP/MASQUE profiles",
	Run: func(cmd *cobra.Command, args []string) {
		err := warpGet(args)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandToolsWarp.AddCommand(commandToolsWarpGet)
}

func warpGet(tags []string) error {
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
	cacheFile := cachefile.New(globalCtx, *options.Experimental.CacheFile)
	err = cacheFile.Start(adapter.StartStateInitialize)
	if err != nil {
		return E.Cause(err, "open cache file")
	}
	defer cacheFile.Close()

	stored, err := loadWarpProfiles(cacheFile, entries)
	if err != nil {
		return err
	}

	for tag, saved := range stored {
		var pretty bytes.Buffer
		if json.Indent(&pretty, saved.Content, "", "  ") != nil {
			pretty.Reset()
			pretty.Write(saved.Content)
		}
		fmt.Printf("%s (%s):\n%s\n", tag, entries[tag], pretty.Bytes())
	}
	return nil
}
