package parser

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type _SingBoxDocument struct {
	Outbounds []option.Outbound `json:"outbounds"`
}
type SingBoxDocument _SingBoxDocument

func (o *SingBoxDocument) UnmarshalJSONContext(ctx context.Context, inputContent []byte) error {
	var content badjson.JSONObject
	err := content.UnmarshalJSONContext(ctx, inputContent)
	if err != nil {
		return err
	}
	outbounds, ok := content.Get("outbounds")
	if !ok {
		return E.New("missing outbounds in sing-box configuration")
	}
	var outs badjson.JSONArray
	for i, outbound := range outbounds.(badjson.JSONArray) {
		typeVal, loaded := outbound.(*badjson.JSONObject).Get("type")
		if !loaded {
			return E.New("missing type in outbound[", i, "]")
		}
		switch typeVal.(string) {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest:
			continue
		default:
			outs = append(outs, outbound)
		}
	}
	content.Put("outbounds", outs)
	inputContent, err = content.MarshalJSONContext(ctx)
	if err != nil {
		return err
	}
	return json.UnmarshalContext(ctx, inputContent, (*_SingBoxDocument)(o))
}

func ParseBoxSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	options, err := json.UnmarshalExtendedContext[SingBoxDocument](ctx, []byte(content))
	if err != nil {
		return nil, err
	}
	if len(options.Outbounds) == 0 {
		return nil, E.New("no servers found")
	}
	return options.Outbounds, nil
}
