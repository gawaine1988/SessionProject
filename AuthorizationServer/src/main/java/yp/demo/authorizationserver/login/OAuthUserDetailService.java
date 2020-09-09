package yp.demo.authorizationserver.login;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Component;

@Component
@DependsOn("plainPasswordEncoder")
public class OAuthUserDetailService implements UserDetailsService {
    InMemoryUserDetailsManager manager;


    private final PlainPasswordEncoder passwordEncoder;

    @Autowired
    public OAuthUserDetailService(PlainPasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.manager = new InMemoryUserDetailsManager();
        String pwd = this.passwordEncoder.encode("123456");//对密码进行加密
        manager.createUser(User.withUsername("user_1").roles("USER").password(pwd).build());
        manager.createUser(User.withUsername("user_2").roles("USER").password(pwd).build());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return UserTokenVo.builder().nickname(username).avatar("test").build();
    }
}
