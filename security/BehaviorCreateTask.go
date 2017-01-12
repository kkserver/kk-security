package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

type BehaviorCreateTaskResult struct {
	app.Result
	Behavior *Behavior `json:"behavior,omitempty"`
}

type BehaviorCreateTask struct {
	app.Task
	Identity string `json:"identity"`
	Action   string `json:"action"`
	Code     string `json:"code"`
	Result   BehaviorCreateTaskResult
}

func (task *BehaviorCreateTask) GetResult() interface{} {
	return &task.Result
}

func (task *BehaviorCreateTask) GetInhertType() string {
	return "security"
}

func (task *BehaviorCreateTask) GetClientName() string {
	return "Behavior.Create"
}
