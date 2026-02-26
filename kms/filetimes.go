package kms

import "time"

const (
	EpochAsFiletime       = 116444736000000000
	HundredsOfNanoseconds = 10000000
)

func FileTimeToTime(ft int64) time.Time {
	s := (ft - EpochAsFiletime) / HundredsOfNanoseconds
	ns100 := (ft - EpochAsFiletime) % HundredsOfNanoseconds
	return time.Unix(s, ns100*100)
}

func TimeToFileTime(t time.Time) int64 {
	return EpochAsFiletime + t.Unix()*HundredsOfNanoseconds + int64(t.Nanosecond()/100)
}
