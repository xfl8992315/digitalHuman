package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"server/db"

	"github.com/golang-jwt/jwt/v5"
)

// 定义登录成功时的响应结构
type LoginResponse struct {
	Message    string `json:"message"`
	UserID     int    `json:"user_id"`
	Token      string `json:"token"`
	Expiration string `json:"expiration"`
}

var jwtSecret = []byte("change-this-secret")

type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func parseTokenFromRequest(r *http.Request) (*Claims, error) {
	authHeader := r.Header.Get("Authorization")
	var tokenStr string
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr = strings.TrimSpace(authHeader[len("Bearer "):])
	} else {
		tokenStr = r.Form.Get("token")
	}
	if tokenStr == "" {
		return nil, errors.New("missing token")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// 处理登录请求的函数
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// 只接受POST请求
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 解析表单数据
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "请求格式错误"})
		return
	}

	// 获取用户名和密码
	// username := r.Form.Get("username")
	// password := r.Form.Get("password")
	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "用户名和密码不能为空"})
		return
	}

	// 验证用户名和密码
	// if username == "15387119665" && password == "123456789" {
	user, err := db.FindUserByCredentials(username, password)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"detail": "用户名或密码错误"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"detail": "服务器错误"})
		return
	}
	if time.Now().After(user.ExpireAt) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "账号已过期"})
		return
	}

	expiresAt := time.Now().Add(2 * time.Hour)
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		IsAdmin:  user.Username == "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   fmt.Sprint(user.ID),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"detail": "生成 token 失败"})
		return
	}
	if err := db.UpdateUserToken(user.ID, token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"detail": "更新 token 失败"})
		return
	}
	// 构造响应数据
	response := LoginResponse{
		Message:    "登录成功",
		UserID:     int(user.ID),
		Token:      token,
		Expiration: user.ExpireAt.Format("2006-01-02 15:04:05"),
	}

	// 设置响应头为JSON
	w.Header().Set("Content-Type", "application/json")

	// 编码并发送响应
	json.NewEncoder(w).Encode(response)
	// } else {
	// 	// 认证失败
	// 	w.WriteHeader(http.StatusUnauthorized)
	// 	json.NewEncoder(w).Encode(map[string]string{"detail": "用户名或密码错误"})
	// }
}

// 处理受保护接口的函数
func handleProtected(w http.ResponseWriter, r *http.Request) {
	// 只接受POST请求
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 解析表单数据
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "请求格式错误"})
		return
	}

	token := r.Form.Get("token")
	userIDStr := r.Form.Get("user_id")
	if token == "" || userIDStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "token 和 user_id 不能为空"})
		return
	}

	var userID uint
	if _, err := fmt.Sscan(userIDStr, &userID); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "user_id 非法"})
		return
	}

	user, err := db.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"detail": "用户不存在"})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"detail": "服务器错误"})
		return
	}

	if user.Token == "" || user.Token != token {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "token 无效"})
		return
	}

	if time.Now().After(user.ExpireAt) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "账号已过期"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Access granted"})
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "请求格式错误"})
		return
	}

	claims, err := parseTokenFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "未授权"})
		return
	}

	if !claims.IsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"detail": "只有管理员可以创建用户"})
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "用户名和密码不能为空"})
		return
	}

	expireAt := time.Now().AddDate(1, 0, 0)
	user, err := db.CreateUser(username, password, expireAt)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "创建用户失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "创建用户成功",
		"user_id":  user.ID,
		"username": user.Username,
	})
}

func handleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "请求格式错误"})
		return
	}

	claims, err := parseTokenFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "未授权"})
		return
	}

	if !claims.IsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"detail": "只有管理员可以查看用户列表"})
		return
	}

	users, err := db.ListUsers()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"detail": "获取用户列表失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "请求格式错误"})
		return
	}

	claims, err := parseTokenFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "未授权"})
		return
	}

	if !claims.IsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"detail": "只有管理员可以删除用户"})
		return
	}

	idStr := r.Form.Get("user_id")
	if idStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "user_id 不能为空"})
		return
	}

	var id uint
	if _, err := fmt.Sscan(idStr, &id); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "user_id 非法"})
		return
	}

	if err := db.DeleteUserByID(id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"detail": "删除用户失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "删除用户成功"})
}

func handleUpdateUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "请求格式错误"})
		return
	}

	claims, err := parseTokenFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "未授权"})
		return
	}

	if !claims.IsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"detail": "只有管理员可以修改密码"})
		return
	}

	idStr := r.Form.Get("user_id")
	newPassword := r.Form.Get("password")
	if idStr == "" || newPassword == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "user_id 和 password 不能为空"})
		return
	}

	var id uint
	if _, err := fmt.Sscan(idStr, &id); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "user_id 非法"})
		return
	}

	if err := db.UpdateUserPassword(id, newPassword); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"detail": "修改密码失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "修改密码成功"})
}

func handleUpdateUserExpireAt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "请求格式错误"})
		return
	}

	claims, err := parseTokenFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "未授权"})
		return
	}

	if !claims.IsAdmin {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"detail": "只有管理员可以修改过期时间"})
		return
	}

	idStr := r.Form.Get("user_id")
	expireStr := r.Form.Get("expire_at")
	if idStr == "" || expireStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "user_id 和 expire_at 不能为空"})
		return
	}

	var id uint
	if _, err := fmt.Sscan(idStr, &id); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "user_id 非法"})
		return
	}

	expireAt, err := time.Parse("2006-01-02 15:04:05", expireStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"detail": "expire_at 格式应为 2006-01-02 15:04:05"})
		return
	}

	if err := db.UpdateUserExpireAt(id, expireAt); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"detail": "修改过期时间失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "修改过期时间成功"})
}
