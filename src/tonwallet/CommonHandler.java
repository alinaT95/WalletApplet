package tonwallet ;

import javacard.framework.*;
import org.globalplatform.GPSystem;
import static tonwallet.ErrorCodes.*;
import static tonwallet.Constants.*;

public class CommonHandler  
{    
	private static SerialNumberHandler serialNumberHandler;  
    private static CommonSecretHandler commonSecretHandler;
    private static CardAuthenticationHandler cardAuthenticationHandler;
    
    private static CommonHandler commonHandler;
    
    private CommonHandler() {
    	serialNumberHandler = SerialNumberHandler.getInstance();
	    commonSecretHandler = CommonSecretHandler.getInstance();
	    cardAuthenticationHandler = CardAuthenticationHandler.getInstance();
    }
    
    public static CommonHandler getInstance() {
		if (commonHandler == null)
			commonHandler = new CommonHandler();
		return commonHandler;
	}
    
    /*
    This command finishes personalization and sets the mode that waits authentication of password.      
    CLA: 0xB0
	INS: 0x90
	P1: 0x00 
	P2: 0x00
    */
    public void finishPers(APDU apdu) {
    	if (!(commonSecretHandler.isEncryptedCommonSecretSet() 
			&& cardAuthenticationHandler.isEncryptedPasswordSet()
			&& serialNumberHandler.isSerialNumberSet())) {
	    	ISOException.throwIt(SW_PERSONALIZATION_NOT_FINISHED);
    	}
        GPSystem.setCardContentState(APP_WAITE_AUTHORIZATION_MODE);
    }
    

	/*
	This command returns the code of applet state.	
	CLA: 0xB0
	INS: 0xC1
	P1: 0x00 
	P2: 0x00
	*/
    public void getAppInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = GPSystem.getCardContentState();
        short le = apdu.setOutgoing();
		if (le != (short) 0x01) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		apdu.setOutgoingLength((short) 0x01);
		apdu.sendBytes((short) 0x00, (short) 0x01);   
    }    
}



