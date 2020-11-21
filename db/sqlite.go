package db

import (
	"fmt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm/schema"
	"log"
	"time"

	"github.com/bruce-qin/EasyGoLib/utils"
	_ "gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Model struct {
	ID        string         `structs:"id" gorm:"primary_key" form:"id" json:"id"`
	CreatedAt utils.DateTime `structs:"-" json:"createdAt" gorm:"type:datetime"`
	UpdatedAt utils.DateTime `structs:"-" json:"updatedAt" gorm:"type:datetime"`
	// DeletedAt *time.Time `sql:"index" structs:"-"`
}

var SQLite *gorm.DB

func Init() (err error) {
	dbFile := utils.DBFile()
	log.Println("db file -->", utils.DBFile())
	SQLite, err = gorm.Open(sqlite.Open(fmt.Sprintf("%s?loc=Asia/Shanghai", dbFile)), &gorm.Config{
		Logger:      DefaultGormLogger,
		PrepareStmt: true,
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "t_",
			SingularTable: true,
		},
	})
	if err != nil {
		return
	}
	// Sqlite cannot handle concurrent writes, so we limit sqlite to one connection.
	// see https://github.com/mattn/go-sqlite3/issues/274
	db, err := SQLite.DB()
	if err != nil {
		return
	}
	db.SetMaxOpenConns(32)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(time.Duration(30) * time.Second)
	return
}

func Close() {
	if SQLite != nil {
		if db, err := SQLite.DB(); err != nil {
			fmt.Printf("close db error:%v", err)
		} else {
			db.Close()
		}
		SQLite = nil
	}
}
