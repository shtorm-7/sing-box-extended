package interrupt

import "context"

type contextKeyIsExternalConnection struct{}

func ContextWithIsExternalConnection(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIsExternalConnection{}, true)
}

func IsExternalConnectionFromContext(ctx context.Context) bool {
	return ctx.Value(contextKeyIsExternalConnection{}) != nil
}

type contextKeyIsProviderConnection struct{}

func ContextWithIsProviderConnection(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIsProviderConnection{}, true)
}

func IsProviderConnectionFromContext(ctx context.Context) bool {
	return ctx.Value(contextKeyIsProviderConnection{}) != nil
}
