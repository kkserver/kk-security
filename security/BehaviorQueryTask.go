package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

type BehaviorQueryCounter struct {
	PageIndex int `json:"p"`
	PageSize  int `json:"size"`
	PageCount int `json:"count"`
}

type BehaviorQueryResult struct {
	app.Result
	Behaviors []Behavior            `json:"behaviors,omitempty"`
	Counter   *BehaviorQueryCounter `json:"counter,omitempty"`
}

type BehaviorQueryTask struct {
	app.Task
	Id        int64  `json:"uid,string"`
	Identity  string `json:"identity"`
	Action    string `json:"action"`
	Code      string `json:"code"`
	Prefix    string `json:"prefix"`
	OrderBy   string `json:"orderBy"` // asc,desc
	PageIndex int    `json:"p"`
	PageSize  int    `json:"size"`
	Counter   bool   `json:"counter"`
	Result    BehaviorQueryResult
}

func (T *BehaviorQueryTask) GetResult() interface{} {
	return &T.Result
}

func (task *BehaviorQueryTask) GetInhertType() string {
	return "security"
}

func (task *BehaviorQueryTask) GetClientName() string {
	return "Behavior.Query"
}
