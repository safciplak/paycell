package main

import (
	"context"
	"encoding/json"
	"fmt"
	sentryhttp "github.com/getsentry/sentry-go/http"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/gorilla/mux"
	"github.com/ozgur-yalcin/paycell.go/app"
	paycell "github.com/ozgur-yalcin/paycell.go/src"
	"github.com/rs/cors"
	"log"
	"net/http"
	"os"
)

const defaultPORT = "8080"

const (
	envmode  = "TEST"                // Çalışma ortamı (Production : "PROD" - Test : "TEST")
	merchant = "9998"                // İşyeri numarası
	appname  = "PAYCELLTEST"         // Uygulama adı
	apppass  = "PaycellTestPassword" // Uygulama şifresi
	storekey = "PAYCELL12345"        // İşyeri anahtarı
	prefix   = "666"                 // Referans no ilk 3 hanesi
)

type SellRequest struct {
	PhoneNumber     string `json:"phone_number"`
	CardNumber      string `json:"card_number"`
	Amount          string `json:"amount"`
	Currency        string `json:"currency"`
	CardExpiryMonth string `json:"card_expiry_month"`
	CardExpiryYear  string `json:"card_expiry_year"`
	CVV             string `json:"cvv"`
	Installment     string `json:"installment"`
}

func (rr SellRequest) Validate(r *http.Request) error {
	return validation.ValidateStruct(&rr,
		validation.Field(&rr.PhoneNumber, validation.Required),
		validation.Field(&rr.CardNumber, validation.Required),
		validation.Field(&rr.Amount, validation.Required),
		validation.Field(&rr.Currency, validation.Required),
		validation.Field(&rr.CardExpiryMonth, validation.Required),
		validation.Field(&rr.CardExpiryYear, validation.Required),
		validation.Field(&rr.CVV, validation.Required),
		validation.Field(&rr.Installment, validation.Required),
	)
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/health-check", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})

	r.HandleFunc("/sell", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		var sr SellRequest
		if !app.BindAndValidate(w, r, &sr) {
			return
		}

		api, req := paycell.Api(merchant, apppass, appname)
		api.SetStoreKey(storekey)
		api.SetPrefix(prefix)
		api.SetMode(envmode)
		api.SetIPAddress(app.GetRealIp(r))                       // IP adresi (zorunlu)
		api.SetPhoneNumber(sr.PhoneNumber)                       // Müşteri numarası (zorunlu)
		api.SetAmount(sr.Amount, sr.Currency)                    // Satış tutarı (zorunlu)
		req.SetCardNumber(sr.CardNumber)                         // Kart numarası (zorunlu)
		req.SetCardExpiry(sr.CardExpiryMonth, sr.CardExpiryYear) // Son kullanma tarihi - AA,YY (zorunlu)
		req.SetCardCode(sr.CVV)                                  // Kart arkasındaki 3 haneli numara (zorunlu)
		req.Provision.Installment = sr.Installment               // Taksit sayısı (varsa)

		if res, err := api.Auth(ctx, req); err == nil {
			pretty, _ := json.MarshalIndent(res.Provision, " ", " ")
			fmt.Println(string(pretty))
		} else {
			app.InternalError(w, r, err)
		}

		w.WriteHeader(http.StatusOK)

	}).Methods(http.MethodPost)

	// start the http server
	log.Printf("Listening on port: %s", getADDR())

	sentryHandler := sentryhttp.New(sentryhttp.Options{Repanic: true})

	handler := cors.AllowAll().Handler(sentryHandler.Handle(r))

	if err := http.ListenAndServe(getADDR(), handler); err != nil {
		log.Fatal(err)
	}
}

func getADDR() string {
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":" + defaultPORT
}
