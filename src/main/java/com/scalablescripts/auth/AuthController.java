package com.scalablescripts.auth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api")
public class AuthController {

    @GetMapping(value = "/hello")
    public String hello() {
        return "Hello!";
    }
}
