/*
 * Created by Dean Stevick <dfaworks@gmail.com> on December 8, 2024
 *
 * Portions derived from Keycloak 2FA SMS Authenticator
 * https://github.com/dasniko/keycloak-2fa-sms-authenticator
 *
 * Copyright © 2025 BEAR, Inc.  All Rights Reserved.
 */
package netzbegruenung.keycloak.authenticator.gateway;

import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.MessageAttributeValue;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;
import software.amazon.awssdk.regions.Region;

/**
 * Amazon Web Services SMS sender
 *
 * @author Dean Stevick <dfaworks@gmail.com>
 */
public class AwsSmsService implements SmsService {

    private static final Logger logger = Logger.getLogger( AwsSmsService.class );
    private static final SnsClient sns = SnsClient.builder().region( Region.US_EAST_1 ).build();//SnsClient.create();
    private static final Pattern PLUS_PREFIXP_PATTERN = Pattern.compile( "\\+" );

    private final String senderId;
    private final String countryCode;

    AwsSmsService( Map<String, String> config ) {
        senderId = config.get( "senderId" );
        countryCode = config.getOrDefault( "countrycode", "" );
    }

    @Override
    public void send( String phoneNumber, String message ) {
        String cleanPhoneNumber = cleanUpPhoneNumber( phoneNumber, countryCode );

        Map<String, MessageAttributeValue> messageAttributes = new HashMap<>();
        // Use "AWS.SNS.SMS.SenderID" for Sender ID vs. Origination Number
        messageAttributes.put( "AWS.MM.SMS.OriginationNumber",
                               MessageAttributeValue.builder().stringValue( senderId ).dataType( "String" ).build() );
        messageAttributes.put( "AWS.SNS.SMS.SMSType",
                               MessageAttributeValue.builder().stringValue( "Transactional" ).dataType( "String" ).build() );

        sns.publish( builder -> builder
                .message( message )
                .phoneNumber( cleanPhoneNumber )
                .messageAttributes( messageAttributes ) );
    }

    private static String cleanUpPhoneNumber( String phoneNumber, String countryCodePrefix ) {
        /*
         * This function tries to correct several common user errors. If there is no default country
         * prefix, this function does not dare to touch the phone number.
         * https://en.wikipedia.org/wiki/List_of_mobile_telephone_prefixes_by_country
         */
        if ( countryCodePrefix == null || countryCodePrefix.isEmpty() ) {
            logger.infof( "Clean phone number: no country code set, return %s", phoneNumber );
            return phoneNumber;
        }

        String countryNumber = PLUS_PREFIXP_PATTERN.matcher( countryCodePrefix ).replaceFirst( "" );
        // convert 49 to +49
        if ( phoneNumber.startsWith( countryNumber ) ) {
            phoneNumber = phoneNumber.replaceFirst( countryNumber, countryCodePrefix );
            logger.infof( "Clean phone number: convert %s to +%s, set phone number to %s",
                          countryNumber, countryNumber, phoneNumber );
        }

        // convert 0049 to +49
        if ( phoneNumber.startsWith( "00" + countryNumber ) ) {
            phoneNumber = phoneNumber.replaceFirst( "00" + countryNumber, countryCodePrefix );
            logger.infof( "Clean phone number: convert 00%s to +%s, set phone number to %s",
                          countryNumber, countryNumber, phoneNumber );
        }

        // convert +490176 to +49176
        if ( phoneNumber.startsWith( countryCodePrefix + "0" ) ) {
            phoneNumber = phoneNumber.replaceFirst( "\\+" + countryNumber + "0", countryCodePrefix );
            logger.infof( "Clean phone number: convert +%s0 to +%s, set phone number to %s",
                          countryNumber, countryNumber, phoneNumber );
        }

        // convert 0 to +49
        if ( phoneNumber.startsWith( "0" ) ) {
            phoneNumber = phoneNumber.replaceFirst( "0", countryCodePrefix );
            logger.infof( "Clean phone number: convert 0 to +%s, set phone number to %s",
                          countryNumber, phoneNumber );
        }

        // lastly add a missing prefix
        if ( !phoneNumber.startsWith( "+" ) ) {
            phoneNumber = countryCodePrefix + phoneNumber;
            logger.infof( "Clean phone number: adding missing country code %s, set phone number to %s",
                          countryCodePrefix, phoneNumber );
        }

        return phoneNumber;
    }
}
