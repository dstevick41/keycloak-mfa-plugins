/*
 * Created by Dean Stevick <dfaworks@gmail.com> on December 8, 2024
 *
 * Copyright © 2025 BEAR, Inc.  All Rights Reserved.
 */
package netzbegruenung.keycloak.authenticator;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Time based OTP Direct Grant Authentication factory
 *
 * @author Dean Stevick <dfaworks@gmail.com>
 */
public class TimeOtpDirectGrantAuthenticatorFactory implements AuthenticatorFactory {

    private static final TimeOtpDirectGrantAuthenticator SINGLETON = new TimeOtpDirectGrantAuthenticator();

    public static final String PROVIDER_ID = "direct-grant-validate-totp";

    @Override
    public Authenticator create( KeycloakSession ks ) {
        // a common pattern in Keycloak codebase is to use singletons for factories
        return SINGLETON;
    }

    @Override
    public void init( Config.Scope scope ) {
    }

    @Override
    public void postInit( KeycloakSessionFactory ksf ) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Time Direct Grant OTP";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Validates a Direct Grant Time (App) based OTP.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                new ProviderConfigProperty( "otpperiod", "OTP grace period", "Time in days between OTP checks",
                                            ProviderConfigProperty.STRING_TYPE, "7" ),
                new ProviderConfigProperty( "exemptips", "Exempt IP Addresses", "A comma separated list of IP Addresses exempt from OTP validation",
                                            ProviderConfigProperty.STRING_TYPE, Collections.emptyList() )
        );
    }

}
