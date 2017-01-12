package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

type BehaviorRemoveTaskResult struct {
	app.Result
}

type BehaviorRemoveTask struct {
	app.Task
	Id       int64  `json:"id,string"`
	Identity string `json:"identity"`
	Action   string `json:"action"`
	Code     string `json:"code"`
	Prefix   string `json:"prefix"`
	Result   BehaviorRemoveTaskResult
}

func (task *BehaviorRemoveTask) GetResult() interface{} {
	return &task.Result
}

func (task *BehaviorRemoveTask) GetInhertType() string {
	return "security"
}

func (task *BehaviorRemoveTask) GetClientName() string {
	return "Behavior.Remove"
}
