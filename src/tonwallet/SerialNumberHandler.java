package tonwallet ;

import javacard.framework.*;
import static tonwallet.Constants.*;
import static tonwallet.ErrorCodes.*;

public class SerialNumberHandler  
{
	private byte[] serialNumber;
	
	private boolean isSerialNumberSet = false;
	
	private static SerialNumberHandler serialSecretHandler;
	
	public static SerialNumberHandler getInstance() {
		if (serialSecretHandler == null)
			serialSecretHandler = new SerialNumberHandler();
		return serialSecretHandler;
	}
	
	private SerialNumberHandler() {
		serialNumber = new byte[SERIAL_NUMBER_SIZE];
	}
	
	public boolean isSerialNumberSet() {
		return isSerialNumberSet;
	}
	
	public void setSerialNumber(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        
        if((numBytes != byteRead) || (numBytes != SERIAL_NUMBER_SIZE)) {
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        for(short i = 0; i < SERIAL_NUMBER_SIZE; i++) {
	        if (buffer[ISO7816.OFFSET_CDATA + i ] < 0 || buffer[ISO7816.OFFSET_CDATA + i ] > 9) {
		        ISOException.throwIt(SW_SERIAL_NUMBER_INCORRECT_FORMAT);
	        }
        }
									                            		             
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, 
			serialNumber, (short) 0x00, SERIAL_NUMBER_SIZE);
		
		isSerialNumberSet = true;    
    }
    
    public void getSerialNumber(APDU apdu) {
    	if (isSerialNumberSet == false) {
	        ISOException.throwIt(SW_SERIAL_NUMBER_IS_NOT_SET);
        }
	    byte[] buffer = apdu.getBuffer();
		short le = apdu.setOutgoing();
		if (le != (short) SERIAL_NUMBER_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		Util.arrayCopyNonAtomic(serialNumber, (short) 0x00, 
			buffer, (short) 0x00, SERIAL_NUMBER_SIZE);
							   
		apdu.setOutgoingLength(SERIAL_NUMBER_SIZE);   
		apdu.sendBytes((short) 0x00, SERIAL_NUMBER_SIZE);  
    }
	

}
