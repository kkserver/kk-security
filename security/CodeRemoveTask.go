package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

type CodeRemoveTaskResult struct {
	app.Result
}

type CodeRemoveTask struct {
	app.Task
	Identity string `json:"identity"`
	Result   CodeRemoveTaskResult
}

func (task *CodeRemoveTask) GetResult() interface{} {
	return &task.Result
}

func (task *CodeRemoveTask) GetInhertType() string {
	return "security"
}

func (task *CodeRemoveTask) GetClientName() string {
	return "Code.Remove"
}
