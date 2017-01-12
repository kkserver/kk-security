package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

type CodeVerifyTaskResult struct {
	app.Result
}

type CodeVerifyTask struct {
	app.Task
	Identity string `json:"identity"`
	Code     string `json:"expires"`
	Result   CodeVerifyTaskResult
}

func (task *CodeVerifyTask) GetResult() interface{} {
	return &task.Result
}

func (task *CodeVerifyTask) GetInhertType() string {
	return "security"
}

func (task *CodeVerifyTask) GetClientName() string {
	return "Code.Verify"
}
