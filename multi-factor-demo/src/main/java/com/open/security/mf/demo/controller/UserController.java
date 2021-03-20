/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.open.security.mf.demo.controller;

import com.open.security.mf.demo.exception.DemoAppException;
import com.open.security.mf.demo.model.Error;
import com.open.security.mf.demo.model.TOTPSecret;
import com.open.security.mf.demo.service.UserService;
import com.open.security.mf.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@Controller
public class UserController {

    @Autowired
    UserService userService;

    @PostMapping(value = "/user",
                 produces = MediaType.TEXT_HTML_VALUE)
    public String addUser(User user, Model model) {

        model.addAttribute(user);
        userService.createUser(user);
        return "registration-response";
    }

    @GetMapping(value = "/user/confirm-account",
                produces = MediaType.TEXT_HTML_VALUE)
    public String confirmAccount(
            @RequestParam(required = true) String otp,
            @RequestParam(required = true) String email,
            Model model) {

        try {
            String totpSecret = userService.confirmAccount(otp, email);
            model.addAllAttributes(Arrays.asList(new TOTPSecret(totpSecret)));
            return "totp-secret";
        } catch (DemoAppException e) {
            model.addAllAttributes(Arrays.asList(new Error(e.getMessage())));
            return "error";
        }
    }

//    @PostMapping(value = "/user/login",
//                 produces = MediaType.TEXT_HTML_VALUE)
//    public String addUser(User user, Model model) {
//
//        model.addAttribute(user);
//        userService.createUser(user);
//        return "registration-response";
//    }
}
