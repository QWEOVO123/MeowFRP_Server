package server

import "github.com/fatedier/frp/pkg/plugin/server"

// Begin fences admission against faults; Opened follows successful Run/Add,
// and Closed follows actual listener closure (not traffic becoming idle).
type ProxyLifecycle struct {
	Begin  func(server.UserInfo) (func(), error)
	Opened func(server.UserInfo, string)
	Closed func(server.UserInfo, string)
}
