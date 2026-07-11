//go:build android

package main

/*
#include <jni.h>
#include <stdlib.h>

static const char* gokms_get_string(JNIEnv *env, jstring value) {
	if (value == NULL) return NULL;
	return (*env)->GetStringUTFChars(env, value, NULL);
}

static void gokms_release_string(JNIEnv *env, jstring value, const char *chars) {
	if (value != NULL && chars != NULL) (*env)->ReleaseStringUTFChars(env, value, chars);
}

static jstring gokms_new_string(JNIEnv *env, const char *value) {
	return (*env)->NewStringUTF(env, value);
}

static void gokms_throw(JNIEnv *env, const char *message) {
	jclass cls = (*env)->FindClass(env, "java/lang/IllegalStateException");
	if (cls != NULL) (*env)->ThrowNew(env, cls, message);
}
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"unsafe"

	"github.com/xmdhs/go-kms/client"
	"github.com/xmdhs/go-kms/kms"
	"github.com/xmdhs/go-kms/logger"
	"github.com/xmdhs/go-kms/server"
)

type synchronizedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *synchronizedBuffer) drain() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := b.buf.String()
	b.buf.Reset()
	return result
}

var (
	serverMu      sync.Mutex
	servers             = make(map[int64]*server.KMSServer)
	nextServerID  int64 = 1
	nativeLogSink synchronizedBuffer
)

func init() {
	logger.InitWriter("INFO", &nativeLogSink)
}

func goString(env *C.JNIEnv, value C.jstring) string {
	chars := C.gokms_get_string(env, value)
	if chars == nil {
		return ""
	}
	defer C.gokms_release_string(env, value, chars)
	return C.GoString(chars)
}

func newJavaString(env *C.JNIEnv, value string) C.jstring {
	chars := C.CString(value)
	defer C.free(unsafe.Pointer(chars))
	return C.gokms_new_string(env, chars)
}

func throwJava(env *C.JNIEnv, err error) {
	message := C.CString(err.Error())
	defer C.free(unsafe.Pointer(message))
	C.gokms_throw(env, message)
}

//export Java_com_xmdhs_gokms_GoKmsNative_startServer
func Java_com_xmdhs_gokms_GoKmsNative_startServer(env *C.JNIEnv, _ C.jobject, ipValue C.jstring, port C.jint, epidValue C.jstring, count C.jint, hwidValue C.jstring) C.jlong {
	config := kms.DefaultServerConfig()
	config.IP = goString(env, ipValue)
	config.Port = int(port)
	config.EPID = goString(env, epidValue)
	if count > 0 {
		clientCount := int(count)
		config.ClientCount = &clientCount
	}

	hwid := strings.TrimPrefix(goString(env, hwidValue), "0x")
	if strings.EqualFold(hwid, "RANDOM") {
		uuid := kms.RandomUUID()
		config.HWID = uuid[:8]
	} else {
		decoded, err := hex.DecodeString(hwid)
		if err != nil || len(decoded) != 8 {
			throwJava(env, fmt.Errorf("HWID must be RANDOM or 16 hexadecimal characters"))
			return 0
		}
		config.HWID = decoded
	}

	srv := server.NewKMSServer(config)
	if err := srv.Listen(); err != nil {
		throwJava(env, err)
		return 0
	}

	serverMu.Lock()
	handle := nextServerID
	nextServerID++
	servers[handle] = srv
	serverMu.Unlock()

	go func() {
		if err := srv.Serve(); err != nil {
			logger.LogAttrs(context.Background(), slog.LevelError, "Server error", slog.Any("error", err))
		}
		serverMu.Lock()
		delete(servers, handle)
		serverMu.Unlock()
	}()
	return C.jlong(handle)
}

//export Java_com_xmdhs_gokms_GoKmsNative_stopServer
func Java_com_xmdhs_gokms_GoKmsNative_stopServer(env *C.JNIEnv, _ C.jobject, handle C.jlong) {
	serverMu.Lock()
	srv := servers[int64(handle)]
	delete(servers, int64(handle))
	serverMu.Unlock()
	if srv == nil {
		return
	}
	if err := srv.Close(); err != nil {
		throwJava(env, err)
	}
}

//export Java_com_xmdhs_gokms_GoKmsNative_runClient
func Java_com_xmdhs_gokms_GoKmsNative_runClient(env *C.JNIEnv, _ C.jobject, ipValue C.jstring, port C.jint, modeValue C.jstring, cmidValue C.jstring, nameValue C.jstring) C.jstring {
	config := client.DefaultClientConfig()
	config.IP = goString(env, ipValue)
	config.Port = int(port)
	config.Mode = goString(env, modeValue)
	config.CMID = goString(env, cmidValue)
	config.Machine = goString(env, nameValue)

	var output bytes.Buffer
	if err := client.RunWithWriter(config, &output); err != nil {
		throwJava(env, err)
		return nil
	}
	return newJavaString(env, output.String())
}

//export Java_com_xmdhs_gokms_GoKmsNative_drainServerLogs
func Java_com_xmdhs_gokms_GoKmsNative_drainServerLogs(env *C.JNIEnv, _ C.jobject) C.jstring {
	return newJavaString(env, nativeLogSink.drain())
}

func main() {}
