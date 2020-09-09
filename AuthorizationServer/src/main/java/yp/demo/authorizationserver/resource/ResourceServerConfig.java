package yp.demo.authorizationserver.resource;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    private static final String RESOURCE_ID = "resource-1";

    /**
     * 添加特定于资源服务器的属性
     *
     * @param resources
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources
                .resourceId(RESOURCE_ID);
    }

    /**
     * 使用此配置安全资源的访问规则，配置需要token验证的url。 默认情况下，所有不在"/oauth/**"中的资源都受到保护。
     *
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        // 只有 /security/getUserInfo 需要token验证
        http
                .requestMatchers().antMatchers("/security/getUserInfo")
                .and()
                .authorizeRequests()
                .antMatchers("/security/getUserInfo").access("#oauth2.hasScope('scope1')")
                .antMatchers("/security/getUserSecret").access("#oauth2.hasScope('scope2')")
                .anyRequest().authenticated().and().csrf().disable();
    }
}
