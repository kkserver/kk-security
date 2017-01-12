package security

import (
	"github.com/kkserver/kk-lib/kk/app"
)

var CodeTypes = map[string]string{
	"AZ":   "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"09":   "0123456789",
	"AZ09": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
}

type CodeCreateTaskResult struct {
	app.Result
	Code *Code `json:"code,omitempty"`
}

type CodeCreateTask struct {
	app.Task
	Identity string `json:"identity"`
	Expires  int64  `json:"expires"`
	Type     string `json:"type"`
	Length   int    `json:"length"`
	Result   CodeCreateTaskResult
}

func (task *CodeCreateTask) GetResult() interface{} {
	return &task.Result
}

func (task *CodeCreateTask) GetInhertType() string {
	return "security"
}

func (task *CodeCreateTask) GetClientName() string {
	return "Code.Create"
}
