package service

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/gogf/gf-demo-user/v2/internal/dao"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/gogf/gf/v2/util/gconv"
)

type AuthService struct{}

var Auth = AuthService{}

// SendRegisterCode 发送注册验证码
func (s *AuthService) SendRegisterCode(ctx context.Context, email string) error {
	// 检查邮箱是否已经注册
	registered, err := dao.Auth.IsEmailRegistered(ctx, email)
	if err != nil {
		return err
	}
	if registered {
		return gerror.New("邮箱已被注册")
	}

	// 生成4位随机数字验证码
	rand.Seed(time.Now().UnixNano())
	code := fmt.Sprintf("%04d", rand.Intn(10000))
	glog.Debugf(ctx, "=======================  code for email %s: %s   =====================", email, code)

	// 存储到Redis，5分钟过期
	err = g.Redis().SetEX(ctx, email, code, 5*60)
	if err != nil {
		return gerror.New("验证码发送失败")
	}

	return nil
}

// Register 员工注册
func (s *AuthService) Register(ctx context.Context, email, password, code string) (int64, error) {
	// 验证码校验
	cacheCode, err := g.Redis().Get(ctx, email)
	if err != nil {
		return 0, gerror.New("系统错误")
	}
	if cacheCode.IsNil() {
		return 0, gerror.New("验证码已过期")
	}
	if cacheCode.String() != code {
		return 0, gerror.New("验证码错误")
	}

	// 检查邮箱是否已经注册
	registered, err := dao.Auth.IsEmailRegistered(ctx, email)
	if err != nil {
		return 0, err
	}
	if registered {
		return 0, gerror.New("邮箱已被注册")
	}

	// 直接使用明文密码
	// 插入数据库
	id, err := dao.Auth.RegisterEmployee(ctx, email, password)
	if err != nil {
		return 0, err
	}

	// 删除已使用的验证码
	_, err = g.Redis().Del(ctx, email)
	if err != nil {
		glog.Warning(ctx, "Failed to delete verification code:", err)
	}

	return id, nil
}

// Login 员工登录
func (s *AuthService) Login(ctx context.Context, email, password string) (map[string]interface{}, error) {
	// 直接使用明文密码查询
	employee, err := dao.Auth.GetEmployeeByEmailAndPassword(ctx, email, password)
	if err != nil {
		return nil, err
	}
	if employee == nil {
		return nil, gerror.New("邮箱或密码错误")
	}

	// 生成token (这里简单使用员工ID作为token)
	token := gconv.String(employee.Id)

	result := g.Map{
		"token":      token,
		"expires_in": 3600,
		"user":       employee,
	}

	return result, nil
}

// SendResetCode 发送密码重置验证码
func (s *AuthService) SendResetCode(ctx context.Context, email string) error {
	// 检查邮箱是否存在
	registered, err := dao.Auth.IsEmailRegistered(ctx, email)
	if err != nil {
		return err
	}
	if !registered {
		return gerror.New("邮箱未注册")
	}

	// 生成4位随机数字验证码
	rand.Seed(time.Now().UnixNano())
	code := fmt.Sprintf("%04d", rand.Intn(10000))
	glog.Debugf(ctx, "Password reset verification code for email %s: %s", email, code)

	// 存储到Redis，5分钟过期
	err = g.Redis().SetEX(ctx, "reset_"+email, code, 5*60)
	if err != nil {
		return gerror.New("验证码发送失败")
	}

	return nil
}

// ResetPassword 重置密码
func (s *AuthService) ResetPassword(ctx context.Context, email, newPassword, code string) error {
	// 验证码校验
	cacheCode, err := g.Redis().Get(ctx, "reset_"+email)
	if err != nil {
		return gerror.New("系统错误")
	}
	if cacheCode.IsNil() {
		return gerror.New("验证码已过期")
	}
	if cacheCode.String() != code {
		return gerror.New("验证码错误")
	}

	// 检查邮箱是否存在
	registered, err := dao.Auth.IsEmailRegistered(ctx, email)
	if err != nil {
		return err
	}
	if !registered {
		return gerror.New("邮箱未注册")
	}

	// 直接使用明文密码更新
	err = dao.Auth.UpdatePassword(ctx, email, newPassword)
	if err != nil {
		return err
	}

	// 删除已使用的验证码
	_, err = g.Redis().Del(ctx, "reset_"+email)
	if err != nil {
		glog.Warning(ctx, "Failed to delete reset verification code:", err)
	}

	return nil
}
