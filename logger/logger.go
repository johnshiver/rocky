package logger

import (
	"log"
	"os"
	"sync"
)

// Thanks internet stranger! https://stackoverflow.com/a/43827612/4672648
type PGLogger struct {
	filename string
	*log.Logger
}

var logger *PGLogger
var once sync.Once

func GetLogInstance() *PGLogger {
	once.Do(func() {
		logger = createLogger("~/.pg_borg.log")
	})
	return logger
}

func createLogger(fname string) *PGLogger {
	file, _ := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)

	return &PGLogger{
		filename: fname,
		Logger:   log.New(file, "PG_BORG_", log.Lshortfile),
	}
}
