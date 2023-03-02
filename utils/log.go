package utils

import (
	"fmt"
	"log"
	"os"
)

// Logger struct for logger interfaces
type Logger struct {
	charge string
	stdout *log.Logger
	stderr *log.Logger
}

// NewStdLogger creates that standard logger
func NewLogger(charge string) *Logger {
	l := &Logger{
		charge: charge,
		stdout: log.New(os.Stdout, "", 0),
		stderr: log.New(os.Stderr, "", 0),
	}

	return l
}

// Format fuction to pull/formate premble log data
func (l *Logger) preString(pre []interface{}) string {
	val := ""

	if len(pre) > 0 {
		val += "["
		for i, v := range pre {
			v := fmt.Sprintf("%v", v)
			if v != "" {
				if i > 0 {
					val += ":" + v
				} else {
					val += v
				}
			}
		}
		val += "] "
	}

	return val
}

// Successful stdout formater
func (l *Logger) Successf(pre []interface{}, data string, v ...interface{}) {
	l.stdout.Printf("[+] ["+l.charge+"] "+l.preString(pre)+data+"\n", v...)
}

// Failure stdout formater
func (l *Logger) Failf(pre []interface{}, data string, v ...interface{}) {
	l.stdout.Printf("[-] ["+l.charge+"] "+l.preString(pre)+data+"\n", v...)
}

// Info stdout formater
func (l *Logger) Infof(pre []interface{}, data string, v ...interface{}) {
	l.stdout.Printf("[*] ["+l.charge+"] "+l.preString(pre)+data+"\n", v...)
}

// Error stderr formater
func (l *Logger) Errorf(pre []interface{}, data string, v ...interface{}) {
	l.stderr.Printf("[ERROR] ["+l.charge+"] "+l.preString(pre)+data+"\n", v...)
}

// Fatal stderr formater
func (l *Logger) Fatalf(pre []interface{}, data string, v ...interface{}) {
	l.stderr.Printf("[FATAL] ["+l.charge+"] "+l.preString(pre)+data+"\n", v...)
	os.Exit(1)
}

// Debug stdout formater
func (l *Logger) Debugf(pre []interface{}, data string, v ...interface{}) {
	l.stdout.Printf("[DEBUG] ["+l.charge+"] "+l.preString(pre)+data+"\n", v...)
}

// Standard stdout formater
func (l *Logger) StdOut(data string, v ...interface{}) {
	l.stdout.Printf("["+l.charge+"] "+data+"\n", v...)
}
