package tonwallet ;

import javacard.framework.*;
import com.ftsafe.javacardx.btcmgr.CoinManager;
import static tonwallet.ErrorCodes.*;
import static tonwallet.Constants.*;

public class PinHandler  
{       
    private static final byte PIN_LENGTH = (byte) 0x04;
	    
    private short numPinFails = (short) 0x00;
            
    private ApduDataProtectionHandler apduDataProtectionHandler;
    
    private static PinHandler pinHandler;
	
	public static PinHandler getInstance(){
		if (pinHandler == null)
			pinHandler = new PinHandler();
		return pinHandler;
	}
    
    private PinHandler() {	
		apduDataProtectionHandler = ApduDataProtectionHandler.getInstance(); 
    }
        
    /*
      This function verifies encoded PIN bytes sent in the data field. 
		After 10 fails of PIN verification internal seed will be blocked.
		Keys produced from it will not be available for signing transactions. 
		And then RESET WALLET and GENERATE SEED must be called. It will regenerate seed and reset PIN.
		The default pin is 5555 now.
		
		This version of applet was written for NFC card. 
		It uses special mode PIN_MODE_FROM_API for entering PIN. 
		PIN  bytes are  given to applet as plain text.

		If PIN code = 5555 plain PIN bytes array = 35353535.
     
        CLA: 0xB0
        INS: 0xA2
        P1: 0x00
        P2: 0x00
        Lc: data size (0x44)
        Data: plain PIN bytes (4 bytes) | sault (32 bytes) | mac (32 bytes)
    */   
    public void checkPin(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	
    	short payloadLen = (short)(PIN_LENGTH + SAULT_SIZE);
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		
        short result = CoinManager.verifyPIN(CoinManager.PIN_MODE_FROM_API, 
					buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);
																					
        if (result != 0x00) {
	       numPinFails++;	        
	       if (numPinFails >= MAX_PIN_TRIES_NUM) {
		        ISOException.throwIt(SW_PIN_TRIES_EXPIRED);
	       }	        
		   ISOException.throwIt(SW_INCORRECT_PIN);  		      
        }
        else {
	        numPinFails = 0x00;
	    }	        
    }
    
    public short getNumPinFails(){
	    return numPinFails;
    }   
}




