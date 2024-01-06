package app

import (
	"log"
	"net/http"

	"github.com/getsentry/sentry-go"
)

func initErrorReportingClient() {
	err := sentry.Init(sentry.ClientOptions{
		Dsn:         "",
		Environment: ENV,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			// dont report errors on localhost
			if IsDEV() {
				return nil
			}
			return event
		},
	})
	if err != nil {
		log.Fatalf("unable to init sentry : %s", err)
	}
}

func ReportError(r *http.Request, err error) {
	if ENV != DEV {
		if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
			email, ok := EmailFromContext(r.Context())
			if ok {
				hub.Scope().SetUser(sentry.User{
					Email: email,
				})
			}
			hub.CaptureException(err)
		}
	}
}
