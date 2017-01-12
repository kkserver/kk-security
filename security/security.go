package security

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"github.com/kkserver/kk-lib/kk"
	"github.com/kkserver/kk-lib/kk/app"
	"github.com/kkserver/kk-lib/kk/app/remote"
)

/**
 * 行为记录
 */
type Behavior struct {
	Id       int64  `json:"id"`
	Identity string `json:"identity"`
	Action   string `json:"action"` //行为
	Code     string `json:"code"`   //跟踪代码
	Ctime    int64  `json:"ctime"`
}

/**
 * 验证码
 */
type Code struct {
	Id      int64  `json:"id"`
	Name    string `json:"name"`
	Code    string `json:"code"`
	Expires int64  `json:"expires"`
	Ctime   int64  `json:"ctime"`
}

type SecurityApp struct {
	app.App
	DB *app.DBConfig

	Remote   *remote.Service
	Behavior *BehaviorService

	BehaviorTable kk.DBTable
	CodeTable     kk.DBTable
}

func (C *SecurityApp) GetDB() (*sql.DB, error) {
	return C.DB.Get(C)
}

func EncodeIdentity(identity string) string {
	m := md5.New()
	m.Write([]byte(identity))
	v := m.Sum(nil)
	return hex.EncodeToString(v)
}
