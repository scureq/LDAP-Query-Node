/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sun.identity.sm.RequiredValueValidator;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.ldap.LDAPAuthUtils;

import com.google.inject.assistedinject.Assisted;
import org.forgerock.openam.ldap.LDAPUtilException;
import org.forgerock.openam.sm.annotations.adapters.Password;

import static org.forgerock.LdapQueryNode.HeartbeatTimeUnit.SECONDS;
import static org.forgerock.LdapQueryNode.LdapConnectionMode.LDAP;
import static org.forgerock.LdapQueryNode.LdapConnectionMode.LDAPS;
import static org.forgerock.LdapQueryNode.LdapConnectionMode.START_TLS;

import java.util.stream.Collectors;


/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = LdapQueryNode.Config.class)
public class LdapQueryNode extends AbstractDecisionNode {

    private final Config config;
    private final Realm realm;
    private final Logger logger = LoggerFactory.getLogger(LdapQueryNode.class);
    private LDAPAuthUtils ldapUtil;
    private ResourceBundle bundle;
    private static final String BUNDLE = "org/forgerock/LdapQueryNode";
    /**
     * Configuration for the node.
     */
    public interface Config {

        // Main LDAP Connectivity related section
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        Set<String> primaryServers();

        @Attribute(order = 200)
        Set<String> secondaryServers();

        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        default LdapConnectionMode ldapConnectionMode() {
            return LDAP;
        }

        @Attribute(order = 400, validators = {RequiredValueValidator.class})
        default boolean trustAllServerCertificates() {
            return false;
        }


        @Attribute(order = 500, validators = {RequiredValueValidator.class})
        Set<String> accountSearchBaseDn();

        @Attribute(order = 600, validators = {RequiredValueValidator.class})
        String adminDn();

        @Attribute(order = 700, validators = {RequiredValueValidator.class})
        @Password
        char[] adminPassword();

        // Search configuration section
        @Attribute(order = 800, validators = {RequiredValueValidator.class})
        Set<String> searchFilterAttributes();

        @Attribute(order = 900, validators = {RequiredValueValidator.class})
        String userProfileAttribute();

        @Attribute(order = 1000)
        Optional<String> userSearchFilter();

        @Attribute(order = 1100)
        default boolean saveToSharedState() {
            return false;
        }

        @Attribute(order = 1200)
        Set<String> attributesToSave();

        @Attribute(order = 1300, validators = {RequiredValueValidator.class})
        default SearchScope searchScope() {
            return SearchScope.SUBTREE;
        }

        // Additional configurations

        @Attribute(order = 1400, validators = {RequiredValueValidator.class})
        default int heartbeatInterval() {
            return 10;
        }

        @Attribute(order = 1500, validators = {RequiredValueValidator.class})
        default HeartbeatTimeUnit heartbeatTimeUnit() {
            return SECONDS;
        }

        @Attribute(order = 1600, validators = {RequiredValueValidator.class})
        default int ldapOperationsTimeout() {
            return 0;
        }

    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public LdapQueryNode(@Assisted Config config, @Assisted Realm realm) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.error("LDAP Query Node Started");
        JsonValue newState = context.sharedState.copy();
        Action.ActionBuilder actionBuilder = goTo(true);
        try {
            ldapUtil = initializeLDAP(context);
            String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
            logger.error("Init Username: " + userName);
            ldapUtil.setUserId(userName);
            ldapUtil.searchForUser();
            String userSearchResult = ldapUtil.getState().name();
            logger.error("User Search Result: " + ldapUtil.getState().name());

            switch (userSearchResult) {
                case ("USER_NOT_FOUND"):
                    logger.error("RESULT: User was not found.");
                    actionBuilder = goTo(false);
                    break;
                case ("USER_FOUND"):
                    logger.error("RESULT: User was found.");
                    if (config.saveToSharedState() == true && !config.attributesToSave().isEmpty()) {
                        logger.error("RESULT User attributes found as requested:" + ldapUtil.getUserAttributeValues());
                        ldapUtil.getUserAttributeValues().forEach(newState::put);
                        for (String name : ldapUtil.getUserAttributeValues().keySet()) {
                            String key = name;
                            String value = ldapUtil.getUserAttributeValues().get(name).toString().replace("[","").replace("]","");
                            logger.error("printing... :" + value);
                            newState.put(key, value);
                        }
                    } else {
                        logger.error("No attributes requested to be returned.");
                    }
                    actionBuilder = goTo(true);
                    break;
                case ("SERVER_DOWN"):
                    logger.error("RESULT: Server is down.");
                    actionBuilder = goTo(false);
                    break;
                default:
                    logger.error("RESULT: Unknown result... : " + userSearchResult);
                    actionBuilder = goTo(false);
            }
        } catch (NodeProcessException | LDAPUtilException e) {
            logger.error("Something went wrong! " + e);
            actionBuilder = goTo(false);
        }

        return actionBuilder.replaceSharedState(newState).build();

    }

    private LDAPAuthUtils initializeLDAP(TreeContext context) throws NodeProcessException {
        LDAPAuthUtils ldapUtil;
        bundle = context.request.locales
                .getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        try {
            org.forgerock.opendj.ldap.SearchScope searchScope = config.searchScope().asLdapSearchScope();
            boolean useStartTLS = config.ldapConnectionMode() == START_TLS;
            boolean isSecure = config.ldapConnectionMode() == LDAPS || useStartTLS;
            String baseDn = config.accountSearchBaseDn().stream()
                    .collect(Collectors.joining(","));
            ldapUtil = new LDAPAuthUtils(config.primaryServers(), config.secondaryServers(),
                    isSecure, bundle, baseDn, logger);

            ldapUtil.setScope(searchScope);
            if (config.userSearchFilter().isPresent()) {
                ldapUtil.setFilter(config.userSearchFilter().get());
            }
            ldapUtil.setUserNamingAttribute(config.userProfileAttribute());
            ldapUtil.setUserSearchAttribute(config.searchFilterAttributes());
            ldapUtil.setAuthPassword(config.adminPassword());
            ldapUtil.setAuthDN(config.adminDn());
            ldapUtil.setReturnUserDN(false);
            ldapUtil.setUserAttributes(config.attributesToSave());
            ldapUtil.setTrustAll(config.trustAllServerCertificates());
            ldapUtil.setUseStartTLS(useStartTLS);
            ldapUtil.setBeheraEnabled(false);
            ldapUtil.setDynamicProfileCreationEnabled(true);
            //ldapUtil.setUserAttrs(config.attributesToSave().toArray(new String[0]));
            ldapUtil.setHeartBeatInterval(config.heartbeatInterval());
            ldapUtil.setHeartBeatTimeUnit(config.heartbeatTimeUnit().toString());
            ldapUtil.setOperationTimeout(config.ldapOperationsTimeout());
            logger.error("Init result: \n"
                    + "nbaseDN-> " + config.adminDn()
                    + "\nuserNamingAttr-> " + config.userProfileAttribute()
                    + "\nuserSearchAttr(s)-> " + config.searchFilterAttributes()
                    + "\nsearchFilter-> " + config.userSearchFilter()
                    + "\nsearchScope-> " + searchScope
                    + "\nattributesToSave-> " + config.attributesToSave()
                    + "\nisSecure-> " + isSecure
                    + "\nuseStartTLS-> " + useStartTLS
                    + "\ntrustAll-> " + config.trustAllServerCertificates()
                    + "\nprimaryServers-> " + config.primaryServers()
                    + "\nsecondaryServers-> " + config.secondaryServers()
                    + "\nheartBeatInterval-> " + config.heartbeatInterval()
                    + "\nheartBeatTimeUnit-> " + config.heartbeatTimeUnit()
                    + "\noperationTimeout-> " + config.ldapOperationsTimeout());
        } catch (LDAPUtilException e) {
            logger.error("Init Exception");

            throw new NodeProcessException(bundle.getString("NoServer"), e);
        }
        return ldapUtil;
    }

    public enum SearchScope {
        /**
         * Only the base DN is searched.
         */
        OBJECT(org.forgerock.opendj.ldap.SearchScope.BASE_OBJECT),
        /**
         * Only the single level below (and not the Base DN) is searched.
         */
        ONE_LEVEL(org.forgerock.opendj.ldap.SearchScope.SINGLE_LEVEL),
        /**
         * The Base DN and all levels below are searched.
         */
        SUBTREE(org.forgerock.opendj.ldap.SearchScope.WHOLE_SUBTREE);

        SearchScope(org.forgerock.opendj.ldap.SearchScope searchScope) {
            this.searchScope = searchScope;
        }

        final org.forgerock.opendj.ldap.SearchScope searchScope;

        private org.forgerock.opendj.ldap.SearchScope asLdapSearchScope() {
            return searchScope;
        }
    }

    /**
     * Defines which protocol/operation is used to establish the connection to the LDAP Directory Server.
     */
    public enum LdapConnectionMode {
        /**
         * The connection won't be secured and passwords are transferred in cleartext over the network.
         */
        LDAP,
        /**
         * the connection is secured via SSL or TLS.
         */
        LDAPS,
        /**
         * the connection is secured by using StartTLS extended operation.
         */
        START_TLS
    }

    /**
     * Units used by the heartbeat time interval setting.
     */
    public enum HeartbeatTimeUnit {
        /**
         * Seconds heartbeat time unit.
         */
        SECONDS,
        /**
         * Minute heartbeat time unit.
         */
        MINUTES,
        /**
         * Hour heartbeat time unit.
         */
        HOURS
    }
}
