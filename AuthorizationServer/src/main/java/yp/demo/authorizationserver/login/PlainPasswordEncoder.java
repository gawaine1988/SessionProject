package yp.demo.authorizationserver.login;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class PlainPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence charSequence) {
        return charSequence.toString();
    }

    @Override

    public boolean matches(CharSequence charSequence, String s) {
        return true;

    }
}
