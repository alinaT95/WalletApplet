package tonwallet ;

import javacard.framework.*;
import static tonwallet.ErrorCodes.*;
import static tonwallet.Constants.*;
import org.globalplatform.GPSystem;

public class ApduDataProtectionHandler  
{
	private static final short KEY_SIZE = HmacSha256Impl.KEY_SIZE;
	private static final short MAX_HMAC_FAIL_TRIES = 20;	 	
    
    private static final short PAYLOAD_MAX_SIZE = (short) (255 - HMAC_SIG_SIZE); // 223
    
    private byte[] lensBuf;		
	private byte[] key;	
	private byte[] mac;
	
	private short hmacVerificationFailCounter = 0;
       
    private HmacSha256Impl sigImpl;
        
    private static ApduDataProtectionHandler apduDataProtectionHandler;
	
	public static ApduDataProtectionHandler getInstance() {
		if (apduDataProtectionHandler == null)
			apduDataProtectionHandler = new ApduDataProtectionHandler();
		return apduDataProtectionHandler;
	}
	
	private ApduDataProtectionHandler() {		
		try {
            mac = JCSystem.makeTransientByteArray(HMAC_SIG_SIZE, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
            mac = new byte[HMAC_SIG_SIZE];
		}	
		
		lensBuf = new byte[0x03];	
		key = new byte[KEY_SIZE];
		
		sigImpl = HmacSha256Impl.getInstance();	
	}
	      
    public void generateHmacKey(byte[] commonSecret, byte[] passwordHash) {
	    sigImpl.sign(passwordHash, (short) 0x00,  
			commonSecret, (short) 0x00, COMMON_SECRET_SIZE,
			key, (short) 0x00);
    }
    
    private byte verifyMac(byte[] data, short dataOffset, short dataLen, 
				byte[] macFromHost, short macFromHostOffset) {			
		sigImpl.sign(key, (short) 0x00, data, 
			dataOffset, dataLen, mac, (short) 0x00);							
		byte res = Util.arrayCompare(macFromHost, macFromHostOffset, 
					mac, (short) 0x00, HMAC_SIG_SIZE);															        
        return res;
    }
    
    public void verifyMacOfKey(byte[] key, short offset, short len, 
				byte[] macFromHost, short macFromHostOffset){	
		byte res = verifyMac(key, offset, len, macFromHost, macFromHostOffset);
		if (res != 0x00) {	       	        
		    ISOException.throwIt(SW_DATA_INTEGRITY_CORRUPTED);     
        }		
	}
				
	private void verifyMacForApduDataChunk(APDU apdu, short payloadLen) {							
		byte[] buffer = apdu.getBuffer();
		byte res = verifyMac(buffer, ISO7816.OFFSET_CDATA, payloadLen, 			
				buffer, (short)(ISO7816.OFFSET_CDATA + payloadLen));															        
        if (res != 0x00) {
	        hmacVerificationFailCounter++;	        
	        if (hmacVerificationFailCounter >= MAX_HMAC_FAIL_TRIES) {
		        GPSystem.setCardContentState(Constants.APP_BLOCKED_MODE);
		        ISOException.throwIt(SW_HMAC_VERIFICATION_TRIES_EXPIRED);
	        }	        
		    ISOException.throwIt(SW_INCORRECT_APDU_HMAC);     
        }
        else {
	        hmacVerificationFailCounter = 0x00;
        } 
    }
     
    private void verifySaultAndMacForApduDataChunk(APDU apdu, short payloadLen) {	    
	    if (payloadLen < SAULT_SIZE || payloadLen > PAYLOAD_MAX_SIZE) {
            ISOException.throwIt(SW_INCORRECT_PAYLOAD);
        }
	    
	    byte[] buffer = apdu.getBuffer();		 	    
	    short saultOffset = (short)(ISO7816.OFFSET_CDATA + payloadLen - SAULT_SIZE);        				        
        boolean result = SaultHandler.getInstance().compareSault(buffer, saultOffset);
               
        if (!result) {
	        ISOException.throwIt(SW_INCORRECT_SAULT);
		}
                        
        verifyMacForApduDataChunk(apdu, payloadLen);				
    }
     
     //Do not forget to set payloadLen correctly
	public void verifyInputApduData(APDU apdu, short payloadLen) {	
		byte[] buffer = apdu.getBuffer();				
		short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF); 
        short byteRead = apdu.setIncomingAndReceive();
        short totalExpectectedLen = (short)(payloadLen + HMAC_SIG_SIZE);
                
        if (numBytes != byteRead || numBytes != totalExpectectedLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
                       
        verifySaultAndMacForApduDataChunk(apdu, payloadLen);
	}
	
	public short verifyInputApduDataContainingKeyChunk(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF); 
		short byteRead = apdu.setIncomingAndReceive();
		short lenOfKeyChunk = (short)(buffer[ISO7816.OFFSET_CDATA] & 0xFF);							
		short payloadLen = (short)(0x01 + lenOfKeyChunk + SAULT_SIZE);       
		short totalExpectectedLen = (short)(payloadLen + HMAC_SIG_SIZE);
		       		
		if (numBytes != byteRead || numBytes != totalExpectectedLen
			|| lenOfKeyChunk <= 0 
			|| lenOfKeyChunk > DATA_CHUNK_MAX_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
					
		verifySaultAndMacForApduDataChunk(apdu, payloadLen);	
		
		return lenOfKeyChunk;
	}
	
	public short verifyInputApduDataContainingDataForSigning(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF); 
		short byteRead = apdu.setIncomingAndReceive();
		short lenOfDataForSigning = Util.getShort(buffer, ISO7816.OFFSET_CDATA);					
		short payloadLen = (short)(0x02 + lenOfDataForSigning + SAULT_SIZE);       
		short totalExpectectedLen = (short)(payloadLen + HMAC_SIG_SIZE);
		        		
		if (numBytes != byteRead || numBytes != totalExpectectedLen 
			|| lenOfDataForSigning <= 0 
			|| lenOfDataForSigning > DATA_FOR_SIGNING_MAX_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		verifySaultAndMacForApduDataChunk(apdu, payloadLen);	
		
		return lenOfDataForSigning;
	}
	
	public byte[] verifyInputApduDataContainingDataForSigningAndPath(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF); 
		short byteRead = apdu.setIncomingAndReceive();
		short lenOfDataForSigning = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		
		if (lenOfDataForSigning <= 0 
			|| lenOfDataForSigning > DATA_FOR_SIGNING_MAX_SIZE_FOR_CASE_WITH_PATH) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
					
		short indPathLenOffset = (short)(ISO7816.OFFSET_CDATA + 0x02 + lenOfDataForSigning);
        byte indPathLen = buffer[indPathLenOffset];  
        
        if (indPathLen <= 0 || indPathLen > MAX_IND_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}  
        
        short payloadLen = (short)(0x03 + lenOfDataForSigning + indPathLen + SAULT_SIZE);  
		short totalExpectectedLen = (short)(payloadLen + HMAC_SIG_SIZE);
		        		
		if (numBytes != byteRead  || numBytes != totalExpectectedLen) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		verifySaultAndMacForApduDataChunk(apdu, payloadLen);	
		
		Util.setShort(lensBuf, (short) 0x00, lenOfDataForSigning);
		lensBuf[0x02] = indPathLen;
		
		return lensBuf;
	}	
}

