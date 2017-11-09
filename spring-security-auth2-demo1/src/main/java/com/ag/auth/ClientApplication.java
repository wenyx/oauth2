package com.ag.auth;

import java.security.Principal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 基于github的开放授权平台客户端
 * 1、请求/页面时，打开index.html页面
 * 2、请求/main页面时，检查是否已授权，未授权则进入第三方授权平台进行授权，授权成功返回主页面并打印当前用户名称
 * 3、请求/user页面时，显示当前用户信息
 * 未实现对授权token的管理及配置
 * @author wenyx
 */
@SpringBootApplication
@EnableOAuth2Sso	// 单点登录
@RestController
public class ClientApplication extends WebSecurityConfigurerAdapter {

	@RequestMapping("/main")
	public String home(Principal principal) {
		return "Welcome to the main page "+principal.getName();
	}

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}

	public static void main(String[] args) {
		SpringApplication.run(ClientApplication.class, args);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	    http
	      .antMatcher("/**").authorizeRequests() // 拦截所有请求
	      .antMatchers("/", "/login**", "/webjars/**").permitAll() // 首页，登录页面，静态资源文件不进行认证拦截
	      .anyRequest().authenticated() // 其它所有请求需要进行认证
	      .and().logout().logoutSuccessUrl("/").permitAll() // 添加注销过滤器，注销成功返回首页，首页不进行认证拦截
	      .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
	}
}
