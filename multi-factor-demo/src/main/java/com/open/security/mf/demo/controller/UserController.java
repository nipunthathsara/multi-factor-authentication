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

import com.open.security.mf.demo.service.UserService;
import com.open.security.mf.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

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

    @GetMapping(value = "/user/confirm-account")
    @ResponseBody
    public String confirmAccount(
            @RequestParam(required = true) String otp,
            @RequestParam(required = true) String email) {

        return userService.confirmAccount(otp, email);
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
