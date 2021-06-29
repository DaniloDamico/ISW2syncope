/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.spring.security;

import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.Resource;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.syncope.common.keymaster.client.api.DomainOps;
import org.apache.syncope.common.keymaster.client.api.KeymasterException;
import org.apache.syncope.common.keymaster.client.api.model.Domain;
import org.apache.syncope.common.lib.SyncopeConstants;
import org.apache.syncope.common.lib.types.AuditElements.Result;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.dao.NotFoundException;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.provisioning.api.UserProvisioningManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@Configurable
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    protected static final Logger LOG = LoggerFactory.getLogger(UsernamePasswordAuthenticationProvider.class);

    protected static final Encryptor ENCRYPTOR = Encryptor.getInstance();

    @Autowired
    protected DomainOps domainOps;

    @Autowired
    protected AuthDataAccessor dataAccessor;

    @Autowired
    protected UserProvisioningManager provisioningManager;

    @Autowired
    protected DefaultCredentialChecker credentialChecker;

    @Resource(name = "adminUser")
    protected String adminUser;

    @Resource(name = "adminPassword")
    protected String adminPassword;

    @Resource(name = "adminPasswordAlgorithm")
    protected String adminPasswordAlgorithm;

    @Resource(name = "anonymousUser")
    protected String anonymousUser;

    @Resource(name = "anonymousKey")
    protected String anonymousKey;

    /**
     * @param adminPassword the adminPassword to set
     */
    public void setAdminPassword(final String adminPassword) {
        this.adminPassword = adminPassword;
    }

    /**
     * @param adminPasswordAlgorithm the adminPasswordAlgorithm to set
     */
    public void setAdminPasswordAlgorithm(final String adminPasswordAlgorithm) {
        this.adminPasswordAlgorithm = adminPasswordAlgorithm;
    }

    /**
     * @param anonymousKey the anonymousKey to set
     */
    public void setAnonymousKey(final String anonymousKey) {
        this.anonymousKey = anonymousKey;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) {
        Domain domain;
        if (SyncopeConstants.MASTER_DOMAIN.equals(
                SyncopeAuthenticationDetails.class.cast(authentication.getDetails()).getDomain())) {

            domain = new Domain.Builder(SyncopeConstants.MASTER_DOMAIN).build();
        } else {
            try {
                domain = domainOps.read(
                        SyncopeAuthenticationDetails.class.cast(authentication.getDetails()).getDomain());
            } catch (NotFoundException | KeymasterException e) {
                throw new BadCredentialsException("Could not find domain "
                        + SyncopeAuthenticationDetails.class.cast(authentication.getDetails()).getDomain(), e);
            }
        }

        AtomicReference<String> username = new AtomicReference<>();
        Boolean authenticated;
        AtomicReference<String> delegationKey = new AtomicReference<>();

        if (anonymousUser.equals(authentication.getName())) {
            username.set(anonymousUser);
            credentialChecker.checkIsDefaultAnonymousKeyInUse();
            authenticated = authentication.getCredentials().toString().equals(anonymousKey);
        } else if (adminUser.equals(authentication.getName())) {
            username.set(adminUser);
            if (SyncopeConstants.MASTER_DOMAIN.equals(domain.getKey())) {
                credentialChecker.checkIsDefaultAdminPasswordInUse();
                authenticated = ENCRYPTOR.verify(
                        authentication.getCredentials().toString(),
                        CipherAlgorithm.valueOf(adminPasswordAlgorithm),
                        adminPassword);
            } else {
                authenticated = ENCRYPTOR.verify(
                        authentication.getCredentials().toString(),
                        domain.getAdminCipherAlgorithm(),
                        domain.getAdminPassword());
            }
        } else {
            Triple<User, Boolean, String> authResult = AuthContextUtils.callAsAdmin(domain.getKey(),
                    () -> dataAccessor.authenticate(domain.getKey(), authentication));
            authenticated = authResult.getMiddle();
            if (authResult.getLeft() != null && authResult.getMiddle() != null) {
                username.set(authResult.getLeft().getUsername());

                if (!authenticated) {
                    AuthContextUtils.callAsAdmin(domain.getKey(), () -> {
                        provisioningManager.internalSuspend(
                                authResult.getLeft().getKey(), adminUser, "Failed authentication");
                        return null;
                    });
                }
            }
            delegationKey.set(authResult.getRight());
        }
        if (username.get() == null) {
            username.set(authentication.getPrincipal().toString());
        }

        return finalizeAuthentication(
                authenticated, domain.getKey(), username.get(), delegationKey.get(), authentication);
    }

    protected Authentication finalizeAuthentication(
            final Boolean authenticated,
            final String domain,
            final String username,
            final String delegationKey,
            final Authentication authentication) {

        UsernamePasswordAuthenticationToken token;
        if (BooleanUtils.isTrue(authenticated)) {
            token = AuthContextUtils.callAsAdmin(domain, () -> {
                UsernamePasswordAuthenticationToken upat = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        dataAccessor.getAuthorities(username, delegationKey));
                upat.setDetails(authentication.getDetails());
                dataAccessor.audit(
                        username,
                        delegationKey,
                        Result.SUCCESS,
                        true,
                        authentication,
                        "Successfully authenticated, with entitlements: " + upat.getAuthorities());
                return upat;
            });

            LOG.debug("User {} successfully authenticated, with entitlements {}", username, token.getAuthorities());
        } else {
            AuthContextUtils.callAsAdmin(domain, () -> {
                dataAccessor.audit(
                        username,
                        delegationKey,
                        Result.FAILURE,
                        false,
                        authentication,
                        "Not authenticated");
                return null;
            });

            LOG.debug("User {} not authenticated", username);

            throw new BadCredentialsException("User " + username + " not authenticated");
        }

        return token;
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
