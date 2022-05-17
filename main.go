package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
)

type Data struct {
	Endpoint string  `json:"endpoint"`
	Method   string  `json:"method"`
	Payload  Payload `json:"payload"`
}

type Payload struct {
	ClientID string `json:"client_id"`
	Role     string `json:"role_id"`
}

func main() {
	store := RegoStore()
	regos := initRegoRule()
	data := Data{
		Endpoint: "v1/users",
		Method:   "POST",
		Payload: Payload{
			ClientID: "service",
			Role:     "admin",
		},
	}
	ProcessRego(context.Background(), ProcessOpa{
		Input:     data,
		Module:    regos,
		Pkg:       "sicepat.api",
		Store:     store,
		Directive: "allow",
	})
}

type RegoStores struct {
	ClientID  []string                  `json:"clients"`
	Roles     []string                  `json:"roles"`
	Resources []map[string]RegoEndpoint `json:"resources"`
}

type RegoEndpoint struct {
	Actions []string `json:"actions"`
}

func RegoStore() RegoStores {
	var resp RegoStores
	resp = RegoStores{
		ClientID: []string{
			"service",
		},
		Roles: []string{
			"admin",
		},
		Resources: []map[string]RegoEndpoint{
			{
				"v1/users": RegoEndpoint{
					Actions: []string{
						"POST",
					},
				},
			},
		},
	}

	return resp
}

type (
	RegoRulesType int
)

const (
	DefaultRules RegoRulesType = iota
)

func initRegoRule() string {
	rules := `package sicepat.api

			default allow = false

			allow{
				check_permission
			}

			check_permission{
				input.payload.client_id == data.clients[_]
				input.payload.role_id == data.roles[_]
				getDetailResources := data.resources[_][input.endpoint]
				input.method == getDetailResources["actions"][_]
			}`
	return rules
}

type ProcessOpa struct {
	Input     interface{}
	Module    string
	Store     interface{}
	Pkg       string
	Directive string
}

func ProcessRego(ctx context.Context, data ProcessOpa) interface{} {

	log.Printf("%+v", data.Store)

	t, _ := json.Marshal(data.Store)

	jsonData := make(map[string]interface{})
	if err := util.UnmarshalJSON(t, &jsonData); err != nil {
		log.Println("Error util.UnmarshalJSON : ", err.Error())
		return nil
	}
	store := inmem.NewFromObject(jsonData)

	log.Printf("%+v", store)

	r := rego.New(
		rego.Query("x = data."+data.Pkg+"."+data.Directive),
		rego.Store(store),
		rego.Input(data.Input),
		rego.Module("", data.Module),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		log.Println("Error Evaluation Rego : ", err.Error())
	}

	log.Println("result : ", rs)

	return rs
}
