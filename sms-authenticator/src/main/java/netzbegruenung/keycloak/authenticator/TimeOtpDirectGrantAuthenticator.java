/*
 * Created by Dean Stevick <dfaworks@gmail.com> on December 8, 2024
 *
 * Copyright © 2025 BEAR, Inc.  All Rights Reserved.
 */
package netzbegruenung.keycloak.authenticator;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import static org.keycloak.authentication.authenticators.client.ClientAuthUtil.errorResponse;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.credential.OTPCredentialProviderFactory;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;

/**
 * Performs Time based OTP Direct Grant Authentication

 * @author Dean Stevick <dfaworks@gmail.com>
 */
public class TimeOtpDirectGrantAuthenticator implements Authenticator, CredentialValidator<OTPCredentialProvider> {

    private static final Logger logger = Logger.getLogger( TimeOtpDirectGrantAuthenticator.class );

    @Override
    public void authenticate( AuthenticationFlowContext context ) {
        // Make sure we are configured for this user and realm
        if ( !configuredFor( context.getSession(), context.getRealm(), context.getUser() ) ) {
            if ( context.getExecution().isConditional() ) {
                context.attempted();
            }
            else if ( context.getExecution().isRequired() ) {
                context.getEvent().error( Errors.INVALID_USER_CREDENTIALS );
                Response challengeResponse =
                         errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials" );
                context.failure( AuthenticationFlowError.INVALID_USER, challengeResponse );
            }
            return;
        }

        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

        String totp = inputData.getFirst( "totp" );

        if ( totp == null ) {
            if ( context.getUser() != null ) {
                context.getEvent().user( context.getUser() );
            }

            // Lets see if the user has doesn't need to perform OTP authentication
            String strRemoteAddr = context.getConnection().getRemoteAddr();
            if ( strRemoteAddr != null && !strRemoteAddr.isBlank() ) {

                // Check if the ip is exempted from OTP
                AuthenticatorConfigModel config = context.getAuthenticatorConfig();
                String exemptIPs = config.getConfig().get( "exemptips" );
                if ( exemptIPs != null && !exemptIPs.isBlank() ) {
                    String[] arrIpAddresses = exemptIPs.split( "," );
                    for ( String strIpAddress : arrIpAddresses ) {
                        if ( IpUtils.isEqual( strRemoteAddr, strIpAddress ) ) {
                            // Exempt.  No need to do 2FA
                            context.success();
                            return;
                        }
                    }
                }

                // Check if the user has authenticated within the otp period.
                UserModel user = context.getUser();
                UserModel userModel = context.getSession().users().getUserByUsername( context.getRealm(), user.getUsername() );
                Map<String, List<String>> attributes = userModel.getAttributes();
                List<String> listTtlStr = attributes.get( "ttl" );
                String ttlStr = listTtlStr != null ? listTtlStr.get( 0 ) : "0";
                try {
                    if ( Long.parseLong( ttlStr ) >= System.currentTimeMillis() ) {
                        // Valid.  No need to do 2FA
                        context.success();
                        return;
                    }
                }
                catch ( NumberFormatException ex ) {
                    logger.warn( ex.getMessage(), ex );
                }
            }

            context.challenge( errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(),
                                              "time_otp_missing", "TOTP missing" ) );

            return;
        }

        // Always use default OTP credential in case of direct grant authentication
        String credentialId = getCredentialProvider( context.getSession() )
               .getDefaultCredential( context.getSession(), context.getRealm(), context.getUser() ).getId();

        boolean valid = getCredentialProvider( context.getSession() )
                .isValid( context.getRealm(), context.getUser(),
                          new UserCredentialModel( credentialId, OTPCredentialModel.TYPE, totp ) );
        if ( !valid ) {
            context.getEvent().user( context.getUser() );
            context.getEvent().error( Errors.INVALID_USER_CREDENTIALS );
            Response challengeResponse = errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(),
                                                        "invalid_grant", "Invalid user credentials" );
            context.failure( AuthenticationFlowError.INVALID_USER, challengeResponse );
            return;
        }

        context.success();
    }

    @Override
    public void action( AuthenticationFlowContext afc ) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor( KeycloakSession session, RealmModel realm, UserModel user ) {
        return getCredentialProvider( session ).isConfiguredFor( realm, user, getType( session ) );
    }

    @Override
    public void setRequiredActions( KeycloakSession session, RealmModel realm, UserModel user ) {
        user.addRequiredAction( UserModel.RequiredAction.CONFIGURE_TOTP.name() );
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions( KeycloakSession session ) {
        return Collections.singletonList( (PhoneNumberRequiredActionFactory)session.getKeycloakSessionFactory()
                .getProviderFactory( RequiredActionProvider.class, PhoneNumberRequiredAction.PROVIDER_ID ) );
    }

    @Override
    public void close() {
    }

    @Override
    public OTPCredentialProvider getCredentialProvider( KeycloakSession session ) {
        return (OTPCredentialProvider)session.getProvider( CredentialProvider.class, OTPCredentialProviderFactory.PROVIDER_ID );
    }

}
