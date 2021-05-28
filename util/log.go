package util

import (
	"log"
	"os"
	"runtime"
)

var LOGPATHNAME string

func InitLogFile(LogPath, fileName string) {
	if runtime.GOOS == "windows" {
		if path := os.Getenv("LOGPATH"); path == "" {
			os.Setenv("LOGPATH", LogPath)
			LOGPATHNAME = LogPath + "\\" + fileName
		} else {
			LogPath = path
		}
	} else {
		if path := os.Getenv("LOGPATH"); path == "" {
			os.Setenv("LOGPATH", LogPath)
			LOGPATHNAME = LogPath + "/" + fileName
		} else {
			LogPath = path
		}
	}

	if !IsExist(LogPath) {
		err := CreateDir(LogPath)
		if err == nil {
			if !IsExist(LOGPATHNAME) {
				f, err := os.OpenFile(LOGPATHNAME, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
				if err == nil {
					_, err := f.WriteString("init log file\n")
					if err != nil {
						log.Println("init log file failed!")
					}
				}
				defer f.Close()
			}
		}
	} else {
		if !IsExist(LOGPATHNAME) {
			f, err := os.OpenFile(LOGPATHNAME, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err == nil {
				_, err := f.WriteString("init log file\n")
				if err != nil {
					log.Println("init log file failed!")
				}
			}
			defer f.Close()
		}
	}
}

func Log(msg string) error {
	f, err := os.OpenFile(LOGPATHNAME, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("open log file failed!", err)
		return err
	}
	defer f.Close()
	_, err = f.WriteString(msg)
	if err != nil {
		log.Println("write log file failed!")
	}
	return err
}

//CreateDir  文件夹创建
func CreateDir(path string) error {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return err
	}
	os.Chmod(path, os.ModePerm)
	return nil
}

//IsExist  判断文件夹/文件是否存在  存在返回 true
func IsExist(f string) bool {
	_, err := os.Stat(f)
	return err == nil || os.IsExist(err)
}
