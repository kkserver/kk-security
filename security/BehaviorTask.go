package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

type BehaviorTaskResult struct {
	app.Result
	Behavior *Behavior `json:"behavior,omitempty"`
}

type BehaviorTask struct {
	app.Task
	Id     int64 `json:"id,string"`
	Result BehaviorTaskResult
}

func (task *BehaviorTask) GetResult() interface{} {
	return &task.Result
}

func (task *BehaviorTask) GetInhertType() string {
	return "security"
}

func (task *BehaviorTask) GetClientName() string {
	return "Behavior.Get"
}
