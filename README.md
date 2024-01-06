[![license](https://img.shields.io/:license-mit-blue.svg)](https://github.com/ozgur-yalcin/paycell.go/blob/main/LICENSE.md)
[![documentation](https://pkg.go.dev/badge/github.com/ozgur-yalcin/paycell.go)](https://pkg.go.dev/github.com/ozgur-yalcin/paycell.go/src)

# Paycell.go
Turkcell (Paycell) API with golang

# Installation
```bash
go get github.com/ozgur-yalcin/paycell.go
```

# Satış
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	paycell "github.com/ozgur-yalcin/paycell.go/src"
)

// Pos bilgileri
const (
	envmode  = "TEST"                // Çalışma ortamı (Production : "PROD" - Test : "TEST")
	merchant = "9998"                // İşyeri numarası
	appname  = "PAYCELLTEST"         // Uygulama adı
	apppass  = "PaycellTestPassword" // Uygulama şifresi
	storekey = "PAYCELL12345"        // İşyeri anahtarı
	prefix   = "666"                 // Referans no ilk 3 hanesi
)

func main() {
	api, req := paycell.Api(merchant, apppass, appname)
	api.SetStoreKey(storekey)
	api.SetPrefix(prefix)
	api.SetMode(envmode)
	api.SetIPAddress("127.0.0.1")         // IP adresi (zorunlu)
	api.SetPhoneNumber("905305289290")    // Müşteri numarası (zorunlu)
	api.SetAmount("1.00", "TRY")          // Satış tutarı (zorunlu)
	req.SetCardNumber("4355084355084358") // Kart numarası (zorunlu)
	req.SetCardExpiry("12", "26")         // Son kullanma tarihi - AA,YY (zorunlu)
	req.SetCardCode("000")                // Kart arkasındaki 3 haneli numara (zorunlu)
	req.Provision.Installment = "0"       // Taksit sayısı (varsa)

	ctx := context.Background()
	if res, err := api.Auth(ctx, req); err == nil {
		pretty, _ := json.MarshalIndent(res.Provision, " ", " ")
		fmt.Println(string(pretty))
	} else {
		fmt.Println(err)
	}
}
```

# İade
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	paycell "github.com/ozgur-yalcin/paycell.go/src"
)

// Pos bilgileri
const (
	envmode  = "TEST"                // Çalışma ortamı (Production : "PROD" - Test : "TEST")
	merchant = "9998"                // İşyeri numarası
	appname  = "PAYCELLTEST"         // Uygulama adı
	apppass  = "PaycellTestPassword" // Uygulama şifresi
	storekey = "PAYCELL12345"        // İşyeri anahtarı
	prefix   = "666"                 // Referans no ilk 3 hanesi
)

func main() {
	api, req := paycell.Api(merchant, apppass, appname)
	api.SetStoreKey(storekey)
	api.SetPrefix(prefix)
	api.SetMode(envmode)
	api.SetPhoneNumber("905305289290") // Müşteri numarası (zorunlu)
	api.SetIPAddress("127.0.0.1")      // IP adresi (zorunlu)
	api.SetAmount("1.00", "TRY")       // İade tutarı (zorunlu)
	req.Refund.OriginalRefNo = ""      // Referans numarası (zorunlu)

	ctx := context.Background()
	if res, err := api.Refund(ctx, req); err == nil {
		pretty, _ := json.MarshalIndent(res.Refund, " ", " ")
		fmt.Println(string(pretty))
	} else {
		fmt.Println(err)
	}
}
```

# İptal
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	paycell "github.com/ozgur-yalcin/paycell.go/src"
)

// Pos bilgileri
const (
	envmode  = "TEST"                // Çalışma ortamı (Production : "PROD" - Test : "TEST")
	merchant = "9998"                // İşyeri numarası
	appname  = "PAYCELLTEST"         // Uygulama adı
	apppass  = "PaycellTestPassword" // Uygulama şifresi
	storekey = "PAYCELL12345"        // İşyeri anahtarı
	prefix   = "666"                 // Referans no ilk 3 hanesi
)

func main() {
	api, req := paycell.Api(merchant, apppass, appname)
	api.SetStoreKey(storekey)
	api.SetPrefix(prefix)
	api.SetMode(envmode)
	api.SetPhoneNumber("905305289290") // Müşteri numarası (zorunlu)
	api.SetIPAddress("127.0.0.1")      // IP adresi (zorunlu)
	req.Cancel.OriginalRefNo = ""      // Referans numarası (zorunlu)

	ctx := context.Background()
	if res, err := api.Cancel(ctx, req); err == nil {
		pretty, _ := json.MarshalIndent(res.Cancel, " ", " ")
		fmt.Println(string(pretty))
	} else {
		fmt.Println(err)
	}
}
```

# Mobil ödemeyi etkinleştirme
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	paycell "github.com/ozgur-yalcin/paycell.go/src"
)

// Pos bilgileri
const (
	envmode  = "TEST"                // Çalışma ortamı (Production : "PROD" - Test : "TEST")
	merchant = "9998"                // İşyeri numarası
	appname  = "PAYCELLTEST"         // Uygulama adı
	apppass  = "PaycellTestPassword" // Uygulama şifresi
	storekey = "PAYCELL12345"        // İşyeri anahtarı
	prefix   = "666"                 // Referans no ilk 3 hanesi
)

func main() {
	api, req := paycell.Api(merchant, apppass, appname)
	api.SetStoreKey(storekey)
	api.SetPrefix(prefix)
	api.SetMode(envmode)
	api.SetPhoneNumber("905305289290") // Müşteri numarası (zorunlu)
	api.SetIPAddress("127.0.0.1")      // IP adresi (zorunlu)

	ctx := context.Background()
	if get, err := api.GetPaymentMethods(ctx, req); err == nil {
		if get.PaymentMethods.MobilePayment != nil {
			if !get.PaymentMethods.MobilePayment.IsDcbOpen {
				if get.PaymentMethods.MobilePayment.IsEulaExpired {
					req.MobilePayment.EulaID = get.PaymentMethods.MobilePayment.EulaId
				}
				if open, err := api.OpenMobilePayment(ctx, req); err == nil {
					pretty, _ := json.MarshalIndent(open.MobilePayment, " ", " ")
					fmt.Println(string(pretty))
				} else {
					fmt.Println(err)
				}
			}
		}
	} else {
		fmt.Println(err)
	}
}
```