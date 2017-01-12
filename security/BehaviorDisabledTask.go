package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

type BehaviorDisabledTaskResult struct {
	app.Result
}

type BehaviorDisabledTask struct {
	app.Task
	Identity string `json:"identity"`
	Action   string `json:"action"`
	Code     string `json:"code"`
	Result   BehaviorDisabledTaskResult
}

func (task *BehaviorDisabledTask) GetResult() interface{} {
	return &task.Result
}

func (task *BehaviorDisabledTask) GetInhertType() string {
	return "security"
}

func (task *BehaviorDisabledTask) GetClientName() string {
	return "Behavior.Disabled"
}
