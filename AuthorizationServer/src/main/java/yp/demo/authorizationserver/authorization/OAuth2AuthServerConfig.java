package yp.demo.authorizationserver.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import yp.demo.authorizationserver.login.OAuthUserDetailService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthServerConfig extends AuthorizationServerConfigurerAdapter {
    private final AuthenticationManager authenticationManager;

    private final OAuthUserDetailService userDetailsService;
    // 密码模式授权模式
    private static final String GRANT_TYPE_PASSWORD = "password";
    //授权码模式
    private static final String AUTHORIZATION_CODE = "authorization_code";
    //refresh token模式
    private static final String REFRESH_TOKEN = "refresh_token";
    //简化授权模式
    private static final String IMPLICIT = "implicit";

    private final PasswordEncoder passwordEncoder;


    @Autowired
    public OAuth2AuthServerConfig(AuthenticationManager authenticationManager,
                                  OAuthUserDetailService ouath2UserDetailService,
                                  PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = ouath2UserDetailService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * =================================配置=============================================================
     * 1.
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //配置两个客户端,一个用于password认证一个用于client认证
        clients.inMemory() // 使用in-memory存储
                .withClient("client_1")
                .secret(passwordEncoder.encode("123456"))
                .authorizedGrantTypes("authorization_code")
                .scopes("scope1")
                .redirectUris("http://localhost:8001/service1/user")
                .and()
                .withClient("client2")
                .secret(passwordEncoder.encode("123456"))
                .authorizedGrantTypes("authorization_code")
                .scopes("scope2")
                .redirectUris("http://localhost:8001/service1/user");
    }


    /**
     * 2.认证服务器安全配置
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //基于session认证会用到
        security
                .checkTokenAccess("isAuthenticated()")
                // 认证中心往外面暴露的一个用来获取jwt的SigningKey的服务/oauth/token_key,但我选择在每个资源服务器本地配置SigningKey
                .tokenKeyAccess("isAuthenticated()")
                // 允许表单认证
                // 如果配置，且url中有client_id和client_secret的，则走 ClientCredentialsTokenEndpointFilter
                // 如果没有配置，但是url中没有client_id和client_secret的，走basic认证保护
                .allowFormAuthenticationForClients();
    }


    /**
     * 3.      配置customTokenEnhancer,自定义UserDetailService,token存储策略
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 将增强的token设置到增强链中
//        TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
//        enhancerChain.setTokenEnhancers(Arrays.asList(customTokenEnhancer(), accessTokenConverter()));

        endpoints.tokenStore(jwtTokenStore()).authenticationManager(authenticationManager)
                .accessTokenConverter(accessTokenConverter())
                //必须注入userDetailsService否则根据refresh_token无法加载用户信息
                .userDetailsService(userDetailsService)
                //支持获取token方式
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE, HttpMethod.OPTIONS)
                //刷新token
                .reuseRefreshTokens(true);

    }

    //========================注入=====================================
    // 更改存储token的策略，默认是内存策略,修改为jwt
//    public TokenStore tokenStore() {
//        //return new JdbcTokenStore(dataSource);  //基于session认证
//        return new JwtTokenStore(jwtAccessTokenConverter());  //基于token认证
//    }
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter() {
            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
                String grantType = authentication.getOAuth2Request().getGrantType();
                //授权码和密码模式才自定义token信息
                if (AUTHORIZATION_CODE.equals(grantType) || GRANT_TYPE_PASSWORD.equals(grantType)) {
                    String userName = authentication.getUserAuthentication().getName();
                    // 自定义一些token 信息
                    Map<String, Object> additionalInformation = new HashMap<String, Object>(16);
                    additionalInformation.put("user_name", userName);
                    additionalInformation = Collections.unmodifiableMap(additionalInformation);
                    ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
                }
                OAuth2AccessToken token = super.enhance(accessToken, authentication);
                return token;
            }
        };
        // 设置签署key
        converter.setSigningKey("bcrypt");
        return converter;
    }

    @Bean
    public TokenStore jwtTokenStore() {
        //基于jwt实现令牌（Access Token）保存
        return new JwtTokenStore(accessTokenConverter());
    }



    // 添加自定义token增强器实现颁发额外信息的token,因为默认颁发token的字段只有username和ROLE
//    @Bean
//    public TokenEnhancer customTokenEnhancer() {
//       return (accessToken, authentication) -> {
//           final Map<String, Object> additionalInfo = new HashMap<>(2);
//           UserDetails user = (UserDetails) authentication.getUserAuthentication().getPrincipal();
//           additionalInfo.put("userName", user.getUsername());
//           additionalInfo.put("authorities", user.getAuthorities());
//           ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
//           return accessToken;
//       };
//    }


}
