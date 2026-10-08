package cluster

import "context"

type identityProgressKey struct{}

// A progress report represents completed SQL operations, not a keepalive.
func WithIdentityProgress(ctx context.Context, report func(int64)) context.Context {
	return context.WithValue(ctx, identityProgressKey{}, report)
}

func ReportIdentityProgress(ctx context.Context, completed int64) {
	if report, ok := ctx.Value(identityProgressKey{}).(func(int64)); ok {
		report(completed)
	}
}
