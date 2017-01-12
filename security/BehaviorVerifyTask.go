package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

type BehaviorVerifyTaskResult struct {
	app.Result
}

type BehaviorVerifyTask struct {
	app.Task
	Identity string `json:"identity"`
	Action   string `json:"action"`
	Code     string `json:"code"`
	Result   BehaviorVerifyTaskResult
}

func (task *BehaviorVerifyTask) GetResult() interface{} {
	return &task.Result
}

func (task *BehaviorVerifyTask) GetInhertType() string {
	return "security"
}

func (task *BehaviorVerifyTask) GetClientName() string {
	return "Behavior.Verify"
}
