/*
 * Created by Dean Stevick <dfaworks@gmail.com> on December 8, 2024
 *
 * Copyright © 2025 BEAR, Inc.  All Rights Reserved.
 */
package netzbegruenung.keycloak.authenticator;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import static org.keycloak.authentication.authenticators.client.ClientAuthUtil.errorResponse;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.theme.Theme;
import org.keycloak.util.JsonSerialization;

/**
 * Performs SMS based OTP Direct Grant Authentication
 *
 * @author Dean Stevick <dfaworks@gmail.com>
 */
public class SmsOtpDirectGrantAuthenticator implements Authenticator, CredentialValidator<SmsAuthCredentialProvider> {

    private static final Logger logger = Logger.getLogger( SmsOtpDirectGrantAuthenticator.class );

    // For: auth/realms/BearBase/protocol/openid-connect/token
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

        // Get the users configured mobile number credential
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        UserModel userModel = context.getSession().users().getUserByUsername( context.getRealm(), user.getUsername() );
        Optional<CredentialModel> model = context.getUser().credentialManager()
                                  .getStoredCredentialsByTypeStream( SmsAuthCredentialModel.TYPE ).findFirst();
        String mobileNumber;
        try {
            mobileNumber = JsonSerialization.readValue( model.orElseThrow().getCredentialData(),
                                                        SmsAuthCredentialData.class ).getMobileNumber();
        }
        catch ( IOException e1 ) {
            logger.warn( e1.getMessage(), e1 );
            context.attempted();
            return;
        }

        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

        // Make sure mobileNumber is configured
        if ( mobileNumber == null || mobileNumber.isBlank() ) {
            // Make sure the OTP App auth is configured
            if ( context.getExecution().isConditional() ) {
                context.attempted();
            }
            else if ( context.getExecution().isRequired() ) {
                context.getEvent().error( Errors.INVALID_USER_CREDENTIALS );
                Response challengeResponse =
                         errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials" );
                context.failure( AuthenticationFlowError.INVALID_USER, challengeResponse );
            }
        }

        // Check to see if the SMS OPT was provided or if we need to send one
        String smsotp = inputData.getFirst( "smsotp" );
        int length = Integer.parseInt( config.getConfig().get( "length" ) );
        int ttl = Integer.parseInt( config.getConfig().get( "ttl" ) );
        int otpPeriod = Integer.parseInt( config.getConfig().get( "otpperiod" ) );

        // smsotp was not provided so send a txt message via sms to the mobile number
        if ( smsotp == null ) {
            if ( context.getUser() != null ) {
                context.getEvent().user( context.getUser() );
            }

            try {
                // We can't set notes on the user session since this is a direct grant
                // so we'll save them as UserModel attributes instead

                // Lets see if the user has doesn't need to perform OTP authentication
                String strRemoteAddr = context.getConnection().getRemoteAddr();
                if ( strRemoteAddr != null && !strRemoteAddr.isBlank() ) {

                    // Check if the ip is exempted from OTP
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

                String code = SecretGenerator.getInstance().randomString( length, SecretGenerator.DIGITS );
                Theme theme = session.theme().getTheme( Theme.Type.LOGIN );
                Locale locale = session.getContext().resolveLocale( user );
                String smsAuthText = theme.getEnhancedMessages( realm, locale ).getProperty( "smsAuthText" );
                String smsText = String.format( smsAuthText, code, Math.floorDiv( ttl, 60 ) );

                userModel.setSingleAttribute( "code", code );
                userModel.setSingleAttribute( "ttl", Long.toString( System.currentTimeMillis() + ( ttl * 1000L ) ) );
                context.setUser( userModel );

                SmsServiceFactory.get( config.getConfig() ).send( mobileNumber, smsText );

                context.challenge( errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(),
                                                  "sms_otp_missing", "SMSOTP missing" ) );

                return;
            }
            catch ( IOException e ) {
                context.getEvent().error( Errors.INVALID_USER_CREDENTIALS );
                Response challengeResponse = errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(),
                                                            "sms_not_sent", "Use another method." );
                context.failure( AuthenticationFlowError.INVALID_USER, challengeResponse );
            }

            return;
        }

        Map<String, List<String>> attributes = userModel.getAttributes();
        List<String> listCode = attributes.get( "code" );
        String code = listCode != null ? listCode.get( 0 ) : null;
        List<String> listTtlStr = attributes.get( "ttl" );
        String ttlStr = listTtlStr != null ? listTtlStr.get( 0 ) : null;

        if ( code == null || ttlStr == null ) {
            context.getEvent().error( Errors.INVALID_USER_CREDENTIALS );
            Response challengeResponse = errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(),
                                                        "internal_error", "auth code or ttl missing" );
            context.failure( AuthenticationFlowError.INVALID_USER, challengeResponse );
            return;
        }

        boolean isValid = smsotp.equals( code );
        if ( isValid ) {
            Long lTTL;
            try {
                lTTL = Long.valueOf( ttlStr );
            }
            catch ( NumberFormatException ex ) {
                logger.warn( ex.getMessage(), ex );
                Response challengeResponse = errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(),
                                                            "invalid_grant", "Invalid user credentials" );
                context.failure( AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, challengeResponse );
                return;
            }

            if ( lTTL < System.currentTimeMillis() ) {
                // expired
                Response challengeResponse = errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(),
                                                            "invalid_grant", "Invalid user credentials" );
                context.failure( AuthenticationFlowError.EXPIRED_CODE, challengeResponse );
            }
            else {
                // Valid.  Save off the code ttl
                String optPeriodStr = Long.toString( System.currentTimeMillis() + ( otpPeriod * 24 * 3600 * 1000L ) );
                userModel.setSingleAttribute( "ttl", optPeriodStr );
                context.setUser( userModel );
                context.success();
            }
        }
        else {
            // invalid
            AuthenticationExecutionModel execution = context.getExecution();
            if ( execution.isRequired() ) {
                Response challengeResponse = errorResponse( Response.Status.UNAUTHORIZED.getStatusCode(),
                                                            "invalid_grant", "Invalid user credentials" );
                context.failure( AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse );
            }
            else if ( execution.isConditional() || execution.isAlternative() ) {
                context.attempted();
            }
        }
    }

    // This appears to be for: auth/realms/BearBase/login-actions/token, which we don't use
    @Override
    public void action( AuthenticationFlowContext context ) {
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
        user.addRequiredAction( PhoneNumberRequiredAction.PROVIDER_ID );
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
    public SmsAuthCredentialProvider getCredentialProvider( KeycloakSession session ) {
        return (SmsAuthCredentialProvider)session.getProvider( CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID );
    }

}
