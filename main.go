package main

import (
	"fmt"
	"net/http"

	"server/db"
)

// http://ipvideo.aguola.com/api
// http://localhost:8080/v11/api
func main() {
	db.Init()

	// 注册登录接口的处理函数
	http.HandleFunc("/v11/api/login", handleLogin)
	// 注册受保护接口的处理函数
	http.HandleFunc("/v11/api/protected", handleProtected)
	// 注册创建用户接口（需要管理员 JWT）
	http.HandleFunc("/v11/api/admin/create_user", handleCreateUser)
	// 注册管理员用户管理接口
	http.HandleFunc("/v11/api/admin/users", handleListUsers)
	http.HandleFunc("/v11/api/admin/delete_user", handleDeleteUser)
	http.HandleFunc("/v11/api/admin/update_password", handleUpdateUserPassword)
	http.HandleFunc("/v11/api/admin/update_expire_at", handleUpdateUserExpireAt)
	// 保活 / 健康检查接口
	http.HandleFunc("/v11/api/health", handleHealth)

	// 提供静态前端后台页面
	fs := http.FileServer(http.Dir("admin"))
	http.Handle("/admin/", http.StripPrefix("/admin/", fs))

	// 启动服务器，监听8080端口
	fmt.Println("服务器启动，监听端口8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("服务器启动失败:", err)
	}
}
