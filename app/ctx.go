package app

import "context"

type emailKey struct{}

func WithEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, emailKey{}, email)
}

func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(emailKey{}).(string)
	return email, ok
}
