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

package org.open.security.mf.authenticator.exception;

public class OpenSecurityMfException extends Exception {

    private String code;
    private String message;
    private String description;

    public OpenSecurityMfException(String code, String message, String description) {

        super(message);
        this.code = code;
        this.message = message;
        this.description = description;
    }

    public OpenSecurityMfException(String code, String message, String description, Throwable cause) {

        super(message, cause);
        this.code = code;
        this.message = message;
        this.description = description;
    }
}
