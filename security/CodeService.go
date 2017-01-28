package security

import (
	"github.com/kkserver/kk-lib/kk"
	"github.com/kkserver/kk-lib/kk/app"
	"math/rand"
	"time"
)

type CodeService struct {
	app.Service
	Create *CodeCreateTask
	Remove *CodeRemoveTask
	Verify *CodeVerifyTask
}

func (S *CodeService) Handle(a app.IApp, task app.ITask) error {
	return app.ServiceReflectHandle(a, task, S)
}

func (S *CodeService) HandleCodeCreateTask(a *SecurityApp, task *CodeCreateTask) error {

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	identity := EncodeIdentity(task.Identity)

	charset, ok := CodeTypes[task.Type]

	if !ok {
		charset = CodeTypes["09"]
	}

	length := 4

	if task.Length != 0 {
		length = task.Length
	}

	code := ""

	rand.Seed(time.Now().UnixNano())

	count := len(charset)

	for length > 0 {
		i := rand.Int() % count
		code = code + charset[i:i+1]
		length = length - 1
	}

	var v = Code{}
	var scaner = kk.NewDBScaner(&v)

	rows, err := kk.DBQuery(db, &a.CodeTable, a.DB.Prefix, " WHERE identity=? ORDER BY id ASC LIMIT 1", identity)

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	defer rows.Close()

	if rows.Next() {

		err = scaner.Scan(rows)

		if err != nil {
			task.Result.Errno = ERROR_SECURITY
			task.Result.Errmsg = err.Error()
			return nil
		}

		v.Code = code
		v.Expires = task.Expires
		v.Ctime = time.Now().Unix()

		_, err = kk.DBUpdate(db, &a.CodeTable, a.DB.Prefix, &v)

		if err != nil {
			task.Result.Errno = ERROR_SECURITY
			task.Result.Errmsg = err.Error()
			return nil
		}

	} else {

		v.Identity = identity
		v.Code = code
		v.Expires = task.Expires
		v.Ctime = time.Now().Unix()

		_, err = kk.DBInsert(db, &a.CodeTable, a.DB.Prefix, &v)

		if err != nil {
			task.Result.Errno = ERROR_SECURITY
			task.Result.Errmsg = err.Error()
			return nil
		}

	}

	task.Result.Code = &v

	return nil
}

func (S *CodeService) HandleCodeVerifyTask(a *SecurityApp, task *CodeVerifyTask) error {

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	var now int64 = time.Now().Unix()

	identity := EncodeIdentity(task.Identity)

	var v = Code{}
	var scaner = kk.NewDBScaner(&v)

	rows, err := kk.DBQuery(db, &a.CodeTable, a.DB.Prefix, " WHERE identity=? ORDER BY id ASC LIMIT 1", identity)

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	defer rows.Close()

	if rows.Next() {

		err = scaner.Scan(rows)

		if err != nil {
			task.Result.Errno = ERROR_SECURITY
			task.Result.Errmsg = err.Error()
			return nil
		}

		if task.Code != v.Code {
			task.Result.Errno = ERROR_SECURITY_CODE
			task.Result.Errmsg = "Code error"
			return nil
		} else if now > v.Ctime+v.Expires {
			task.Result.Errno = ERROR_SECURITY_CODE_EXPIRES
			task.Result.Errmsg = "Code has expired"
			return nil
		}

	} else {

		task.Result.Errno = ERROR_SECURITY_NOT_FOUND_CODE
		task.Result.Errmsg = "Not Found Code"
		return nil
	}

	return nil
}

func (S *CodeService) HandleCodeRemoveTask(a *SecurityApp, task *CodeRemoveTask) error {

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	identity := EncodeIdentity(task.Identity)

	kk.DBDelete(db, &a.CodeTable, a.DB.Prefix, " WHERE identity=?", identity)

	return nil
}
