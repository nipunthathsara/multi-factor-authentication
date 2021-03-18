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

package org.open.security.mf.authenticator.util;

import org.apache.commons.lang3.StringUtils;
import org.open.security.mf.authenticator.constant.Constants;
import org.open.security.mf.authenticator.exception.OpenSecurityMfException;

public class Utils {

    public static OpenSecurityMfException handleException(Constants.Error error, String data, Throwable e) {

        String description = error.getDescription();
        if (StringUtils.isNotBlank(data)) {
            String.format(description, data);
        }
        return new OpenSecurityMfException(error.getCode(), error.getMessage(), description, e);
    }

    public static OpenSecurityMfException handleException(Constants.Error error, String data) {

        String description = error.getDescription();
        if (StringUtils.isNotBlank(data)) {
            String.format(description, data);
        }
        return new OpenSecurityMfException(error.getCode(), error.getMessage(), description);
    }
}
