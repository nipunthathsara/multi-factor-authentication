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

package com.open.security.mf.demo.repository;

import com.open.security.mf.demo.model.User;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {

    @Modifying
    @Transactional
    @Query(value = "UPDATE USERS SET STATUS = ?1 WHERE EMAIL = ?2", nativeQuery = true)
    void updateStatus(String status, String email);

    @Query(value = "SELECT * FROM USERS WHERE EMAIL = ?1 AND PASSWORD = ?2", nativeQuery = true)
    User authenticate(String email, String password);

    @Query(value = "SELECT * FROM USERS WHERE EMAIL = ?1", nativeQuery = true)
    User findByEmail(String email);
}
