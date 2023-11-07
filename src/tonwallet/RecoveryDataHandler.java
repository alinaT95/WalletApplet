package tonwallet ;

import javacard.framework.*;
import javacard.security.*;

import static tonwallet.ErrorCodes.*;
import static tonwallet.Constants.*;

public class RecoveryDataHandler  
{
	public static final short RECOVERY_DATA_MAX_SIZE = (short)2048;
	public final static byte START_OF_TRANSMISSION = 0x00;
	public final static byte END_OF_TRANSMISSION = 0x02;
	
	private short realRecoveryDataLen = (short)0x00;
	
	private boolean isRecoveryDataSet = false;
	
	private byte[] recoveryData;
	
	private byte[] recoveryDataHash;
	
	private MessageDigest md;
	
	private static RecoveryDataHandler recoveryDataHandler;
	
	public static RecoveryDataHandler getInstance(){
		if (recoveryDataHandler == null)
			recoveryDataHandler = new RecoveryDataHandler();
		return recoveryDataHandler;
	}
	
	private RecoveryDataHandler() {	
		recoveryData = new byte[RECOVERY_DATA_MAX_SIZE]; 
		recoveryDataHash  = new byte[SHA_HASH_SIZE]; 
		md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }
    
    public void addRecoveryDataPart(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        
        if (isRecoveryDataSet == true) {
	        ISOException.throwIt(SW_RECOVERY_DATA_ALREADY_EXISTS);
        }
        
        byte statusOfTransmission = buffer[ISO7816.OFFSET_P1];
        
        if (statusOfTransmission == START_OF_TRANSMISSION) {
        	realRecoveryDataLen = (short) 0x00;
        }
        
        if (statusOfTransmission != END_OF_TRANSMISSION) {
        	if ((numBytes != byteRead) || ((realRecoveryDataLen + numBytes) > RECOVERY_DATA_MAX_SIZE)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
        	
	        JCSystem.beginTransaction();
			Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, 
				recoveryData, realRecoveryDataLen, numBytes);
			realRecoveryDataLen += numBytes;
			JCSystem.commitTransaction(); 
        }       
        else {
        	if ((numBytes != byteRead) || (numBytes != SHA_HASH_SIZE)) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			md.doFinal(recoveryData, (short)0x00, realRecoveryDataLen, recoveryDataHash, (short) 0x00);	
        	boolean res = Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, 
					recoveryDataHash, (short)0x00, SHA_HASH_SIZE) == 0x00;	
        	
			if (!res) {
				resetRecoveryData();
				ISOException.throwIt(SW_INTEGRITY_OF_RECOVERY_DATA_CORRUPTED);
			}    
			isRecoveryDataSet = true; 					
		 
        }

    }
    
    public void getRecoveryDataLen(APDU apdu) {
    	if (isRecoveryDataSet == false) {
	        ISOException.throwIt(SW_RECOVERY_DATA_IS_NOT_SET);
        }
		byte[] buffer = apdu.getBuffer();
		short le = apdu.setOutgoing();       
        if (le != (short) 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, realRecoveryDataLen);
		apdu.sendBytes((short) 0x00, (short) 0x02);
		
	}
    
    public void getRecoveryDataPart(APDU apdu) {
    	if (isRecoveryDataSet == false) {
	        ISOException.throwIt(SW_RECOVERY_DATA_IS_NOT_SET);
        }
    	byte[] buffer = apdu.getBuffer();
    	short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        
        if ((numBytes != byteRead) || (numBytes != 0x02)) {
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    	short startPos = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
    	
    	short le = apdu.setOutgoing();
    	 
    	if (startPos < 0 || (startPos + le) > RECOVERY_DATA_MAX_SIZE) {
	        ISOException.throwIt(SW_INCORRECT_START_POS_OR_LE);
        }
        
        apdu.setOutgoingLength(le);   
		apdu.sendBytesLong(recoveryData, startPos, le);
    }
    
    public void getHashOfRecoveryData(APDU apdu) {
    	if (isRecoveryDataSet == false) {
	        ISOException.throwIt(SW_RECOVERY_DATA_IS_NOT_SET);
        }
	    byte[] buffer = apdu.getBuffer(); 
	    short le = apdu.setOutgoing();
		if (le != SHA_HASH_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}    
	    md.doFinal(recoveryData, (short) 0x00, realRecoveryDataLen, buffer, (short) 0x00);	  					
		apdu.setOutgoingLength(SHA_HASH_SIZE);
		apdu.sendBytes((short) 0x00, SHA_HASH_SIZE);   
    }
    
    public void resetRecoveryData(APDU apdu) {
    	resetRecoveryData();
    }
    
    public void resetRecoveryData() {
    	Util.arrayFillNonAtomic(recoveryData, (short) 0x00, RECOVERY_DATA_MAX_SIZE, (byte) 0x00);
    	Util.arrayFillNonAtomic(recoveryDataHash, (short) 0x00, SHA_HASH_SIZE, (byte) 0x00);
    	realRecoveryDataLen = (short) 0x00;
    	isRecoveryDataSet = false;
    }
    
    public void isRecoveryDataSet(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	short le = apdu.setOutgoing();
		if (le != (short) 0x01) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		buffer[0x00] = isRecoveryDataSet ? (byte)0x01 : (byte)0x00;
		apdu.setOutgoingLength(le);
		apdu.sendBytes((short) 0x00, le);
    }
	

}
