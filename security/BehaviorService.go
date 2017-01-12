package security

import (
	"bytes"
	"fmt"
	"github.com/kkserver/kk-lib/kk"
	"github.com/kkserver/kk-lib/kk/app"
	"github.com/kkserver/kk-lib/kk/dynamic"
	"strings"
	"time"
)

/**
 * 策略
 */
type BehaviorPloy struct {
	Prefix      string //行为前缀
	MaxCount    int64  //最大行为数量 0 为不限制
	MinInterval int64  //最小间隔秒数 0 为不限制
	Duration    int64  //持续秒数
	Errno       int    //错误代码
	Errmsg      string //错误说明
}

type BehaviorPloyList struct {
	Ploys []*BehaviorPloy
}

func (P *BehaviorPloyList) SetValue(key string, value interface{}) {

	if P.Ploys == nil {
		P.Ploys = []*BehaviorPloy{}
	}

	if strings.HasPrefix(key, "@") {
		v := BehaviorPloy{}
		dynamic.Set(&v, key[1:], value)
		P.Ploys = append(P.Ploys, &v)
	} else if len(P.Ploys) > 0 {
		dynamic.Set(P.Ploys[len(P.Ploys)-1], key, value)
	}

}

type BehaviorService struct {
	app.Service
	Get      *BehaviorTask
	Create   *BehaviorCreateTask
	Verify   *BehaviorVerifyTask
	Remove   *BehaviorRemoveTask
	Query    *BehaviorQueryTask
	Disabled *BehaviorDisabledTask

	Ploys *BehaviorPloyList
}

func (S *BehaviorService) Handle(a app.IApp, task app.ITask) error {
	return app.ServiceReflectHandle(a, task, S)
}

func (S *BehaviorService) HandleBehaviorCreateTask(a *SecurityApp, task *BehaviorCreateTask) error {

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	var v = Behavior{}

	v.Identity = EncodeIdentity(task.Identity)
	v.Action = task.Action
	v.Code = task.Code
	v.Ctime = time.Now().Unix()

	_, err = kk.DBInsert(db, &a.BehaviorTable, a.DB.Prefix, &v)

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	task.Result.Behavior = &v

	return nil
}

func (S *BehaviorService) HandleBehaviorVerifyTask(a *SecurityApp, task *BehaviorVerifyTask) error {

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	var now int64 = time.Now().Unix()

	err = func() error {

		if S.Ploys != nil && S.Ploys.Ploys != nil {

			for _, ploy := range S.Ploys.Ploys {

				if strings.HasPrefix(task.Action, ploy.Prefix) {

					if ploy.MaxCount != 0 || ploy.MinInterval != 0 {

						rows, err := db.Query(fmt.Sprintf("SELECT COUNT(*) as c, MAX(ctime) as ctime FROM %s%s WHERE status=? AND ctime <= ? AND ctime >= ? AND identity=? AND action=? ORDER BY id DESC",
							a.DB.Prefix, a.BehaviorTable.Name),
							BehaviorStatusEnabled, now, now-ploy.Duration, EncodeIdentity(task.Identity), task.Action)

						if err != nil {
							return err
						}

						var vcount interface{} = 0
						var vctime interface{} = 0

						if rows.Next() {

							err = rows.Scan(&vcount, &vctime)

							fmt.Println(vcount, vctime)

							if err != nil {
								return err
							}
						}

						rows.Close()

						count, _ := vcount.(int64)
						ctime, _ := vctime.(int64)

						if (ploy.MaxCount != 0 && count > ploy.MaxCount) || (ploy.MinInterval != 0 && now-ctime < ploy.MinInterval) {
							return app.NewError(ploy.Errno, ploy.Errmsg)
						}
					}
				}

			}

		}

		return nil
	}()

	if err != nil {
		e, ok := err.(*app.Error)
		if ok {
			task.Result.Errno = e.Errno
			task.Result.Errmsg = e.Errmsg
		} else {
			task.Result.Errno = ERROR_SECURITY
			task.Result.Errmsg = err.Error()
		}
	}

	return nil
}

func (S *BehaviorService) HandleBehaviorDisabledTask(a *SecurityApp, task *BehaviorDisabledTask) error {

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	now := time.Now().Unix()

	_, err = db.Exec(fmt.Sprintf("UPDATE %s%s SET status=? WHERE status=? AND ctime <= ? AND identity=? AND action=?",
		a.DB.Prefix, a.BehaviorTable.Name),
		BehaviorStatusDisabled, BehaviorStatusEnabled, now, EncodeIdentity(task.Identity), task.Action)

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	return nil
}

func (S *BehaviorService) HandleBehaviorTask(a *SecurityApp, task *BehaviorTask) error {

	if task.Id == 0 {
		task.Result.Errno = ERROR_SECURITY_NOT_FOUND_ID
		task.Result.Errmsg = "Not found id"
		return nil
	}

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	var v = Behavior{}
	var scanner = kk.NewDBScaner(&v)

	rows, err := kk.DBQuery(db, &a.BehaviorTable, a.DB.Prefix, " WHERE id=?", task.Id)

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	defer rows.Close()

	if rows.Next() {

		err := scanner.Scan(rows)

		if err != nil {
			task.Result.Errno = ERROR_SECURITY
			task.Result.Errmsg = err.Error()
			return nil
		}

		task.Result.Behavior = &v

	} else {
		task.Result.Errno = ERROR_SECURITY_NOT_FOUND_BEHAVIOR
		task.Result.Errmsg = "Not found behavior"
		return nil
	}

	return nil
}

func (S *BehaviorService) HandleBehaviorRemoveTask(a *SecurityApp, task *BehaviorRemoveTask) error {

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	sql := bytes.NewBuffer(nil)

	sql.WriteString(" WHERE 1")

	args := []interface{}{}

	if task.Id != 0 {

		sql.WriteString(" AND id=?")

		args = append(args, task.Id)

	} else {

		if task.Identity != "" {

			sql.WriteString(" AND identity=?")
			args = append(args, EncodeIdentity(task.Identity))

		}

		if task.Action != "" {

			sql.WriteString(" AND action=?")
			args = append(args, task.Action)

		}

		if task.Code != "" {

			sql.WriteString(" AND code=?")
			args = append(args, task.Code)

		}

		if task.Prefix != "" {

			sql.WriteString(" AND action LIKE ?")
			args = append(args, task.Prefix+"%")

		}

	}

	if len(args) > 0 {

		_, err = kk.DBDelete(db, &a.BehaviorTable, a.DB.Prefix, sql.String(), args...)

		if err != nil {
			task.Result.Errno = ERROR_SECURITY
			task.Result.Errmsg = err.Error()
		}

	}

	return nil
}

func (S *BehaviorService) HandleBehaviorQueryTask(a *SecurityApp, task *BehaviorQueryTask) error {

	var db, err = a.GetDB()

	if err != nil {
		task.Result.Errno = ERROR_SECURITY
		task.Result.Errmsg = err.Error()
		return nil
	}

	var behaviors = []Behavior{}

	var args = []interface{}{}

	sql := bytes.NewBuffer(nil)

	sql.WriteString(" WHERE 1")

	if task.Id != 0 {
		sql.WriteString(" AND id=?")
		args = append(args, task.Id)
	} else {

		if task.Identity != "" {

			sql.WriteString(" AND identity=?")
			args = append(args, EncodeIdentity(task.Identity))

		}

		if task.Action != "" {

			sql.WriteString(" AND action=?")
			args = append(args, task.Action)

		}

		if task.Code != "" {

			sql.WriteString(" AND code=?")
			args = append(args, task.Code)

		}

		if task.Prefix != "" {

			sql.WriteString(" AND action LIKE ?")
			args = append(args, task.Prefix+"%")

		}

		var pageIndex = task.PageIndex
		var pageSize = task.PageSize

		if pageIndex < 1 {
			pageIndex = 1
		}

		if pageSize < 1 {
			pageSize = 10
		}

		if task.Counter {
			var counter = BehaviorQueryCounter{}
			counter.PageIndex = pageIndex
			counter.PageSize = pageSize
			counter.PageSize, err = kk.DBQueryCount(db, &a.BehaviorTable, a.DB.Prefix, sql.String(), args...)
			if err != nil {
				task.Result.Errno = ERROR_SECURITY
				task.Result.Errmsg = err.Error()
				return nil
			}
		}

		if task.OrderBy == "asc" {
			sql.WriteString(" ORDER BY id ASC")
		} else {
			sql.WriteString(" ORDER BY id DESC")
		}

		sql.WriteString(fmt.Sprintf(" LIMIT %d,%d", (pageIndex-1)*pageSize, pageSize))

		var v = Behavior{}
		var scanner = kk.NewDBScaner(&v)

		rows, err := kk.DBQuery(db, &a.BehaviorTable, a.DB.Prefix, sql.String(), args...)

		if err != nil {
			task.Result.Errno = ERROR_SECURITY
			task.Result.Errmsg = err.Error()
			return nil
		}

		defer rows.Close()

		for rows.Next() {

			err = scanner.Scan(rows)

			if err != nil {
				task.Result.Errno = ERROR_SECURITY
				task.Result.Errmsg = err.Error()
				return nil
			}

			behaviors = append(behaviors, v)
		}
	}

	task.Result.Behaviors = behaviors

	return nil
}
