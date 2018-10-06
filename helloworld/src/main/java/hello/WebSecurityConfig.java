package hello;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
//WebSecurityConfigurerAdapter 提供了一种便利的方式去创建 WebSecurityConfigurer的实例，
//只需要重写 WebSecurityConfigurerAdapter 的方法，即可配置拦截什么URL、设置什么权限等安全控制。
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    //configure(HttpSecurity)方法定义了哪些URL路径应该被保护，哪些不应该。
    //具体来说，“/”和“/ home”路径被配置为不需要任何身份验证。所有其他路径必须经过身份验证。
    //当用户成功登录时，它们将被重定向到先前请求的需要身份认证的页面。有一个由 loginPage()指定的自定义“/登录”页面，每个人都可以查看它。
    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .authorizeRequests()
                    .antMatchers("/","home").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/loginPage")
                    .loginProcessingUrl("/login")
                    .permitAll()
                    .and()
                // 退出登录，默认情况是，访问URL”/logout”
                // 使HTTP Session无效来清除用户，
                // 清除已配置的任何#rememberMe()身份验证，
                // 清除SecurityContextHolder，
                // 然后重定向到”/login?success”
                .logout()
                    .logoutUrl("/logout")
                    .permitAll();
    }
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{
        auth
                .inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER");
    }
}
