package yp.demo.authorizationserver.resource;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import yp.demo.authorizationserver.login.UserTokenVo;

import java.security.Principal;

@RestController
@RequestMapping("/security")
public class SecurityController {
    @GetMapping("/getUserInfo")
    @ResponseBody
    public UserTokenVo getUserInfo(Principal principal) {
        return UserTokenVo.builder().nickname("testYp").avatar("coder").build();
    }

    @GetMapping("/getUserSecret")
    @ResponseBody
    public UserTokenVo getUserSecret(Principal principal) {
        return UserTokenVo.builder().nickname("testYp").avatar("coder").blogAddress("www.userblog.com").build();
    }
}