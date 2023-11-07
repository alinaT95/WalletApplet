package tonwallet ;

import javacard.framework.*;
import static tonwallet.ErrorCodes.*;
import static tonwallet.Constants.*;
import static tonwallet.Utils.*;
import org.globalplatform.GPSystem;

import javacard.security.*;
import javacardx.crypto.*;

public class CardAuthenticationHandler  
{
	private static final short PASSWORD_SIZE = 128;
	private static final short MAX_PASSWORD_TRIES = 20;
	private static final short AES_IV_LEN = (short) 16;
	
    private static byte[] encryptedPassword; 
    private static byte[] decryptedPassword; 
    private static byte[] aesKeyBytes; 
    private static byte[] decryptedPasswordHash;
       
    private short numPasswordTries = 0x00;
    
    private boolean isEncryptedPasswordSet = false;
    
    private MessageDigest shaMessageDigest;
    
    private Cipher cipherDec;
    private AESKey aesKey;
    
    private static ApduDataProtectionHandler apduDataProtectionHandler;
    private static CommonSecretHandler commonSecretHandler;
           
    private static CardAuthenticationHandler cardAuthenticationHandler;
	
	public static CardAuthenticationHandler getInstance() {
		if (cardAuthenticationHandler == null)
			cardAuthenticationHandler = new CardAuthenticationHandler();
		return cardAuthenticationHandler;
	}
       
    private CardAuthenticationHandler() {
	     encryptedPassword = new byte[PASSWORD_SIZE];  
	     decryptedPassword = new byte[PASSWORD_SIZE]; 
	     aesKeyBytes = new byte[SHA_HASH_SIZE]; 
	     decryptedPasswordHash = new byte[SHA_HASH_SIZE]; 
	     
	     shaMessageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
	     cipherDec = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
	     aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
	     apduDataProtectionHandler = ApduDataProtectionHandler.getInstance();
	     commonSecretHandler = CommonSecretHandler.getInstance();
    }
    
    public boolean isEncryptedPasswordSet() {
	    return isEncryptedPasswordSet;
    }
    
    public void setEncryptedPassword(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        
        if((numBytes != byteRead) || (numBytes != PASSWORD_SIZE)){
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
									                            		             
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, 
			encryptedPassword, (short) 0x00, PASSWORD_SIZE);
		
		isEncryptedPasswordSet = true;	    
    }
       
    public void getHashOfEncryptedPassword(APDU apdu) {     
	    byte[] buffer = apdu.getBuffer();     	    	  					
		short le = apdu.setOutgoing();
		if (le != SHA_HASH_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		shaMessageDigest.doFinal(encryptedPassword, (short)0x00, PASSWORD_SIZE, buffer, (short) 0x00);
		apdu.setOutgoingLength(SHA_HASH_SIZE);
		apdu.sendBytes((short) 0x00, SHA_HASH_SIZE);    
    }
          
    public void verifyPassword(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
        short numBytes = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();
        
        if((numBytes != byteRead) || (numBytes != (short) (PASSWORD_SIZE + AES_IV_LEN))) {
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        shaMessageDigest.doFinal(buffer, ISO7816.OFFSET_CDATA, PASSWORD_SIZE, aesKeyBytes, (short) 0x00);
       
        aesKey.setKey(aesKeyBytes, (short) 0x00);
        short ivOffset = (short)(ISO7816.OFFSET_CDATA + PASSWORD_SIZE);
        cipherDec.init(aesKey, Cipher.MODE_DECRYPT, buffer, 
					ivOffset, AES_IV_LEN);
						
        cipherDec.doFinal(encryptedPassword, (short) 0x00, PASSWORD_SIZE, 
				decryptedPassword, (short) 0x00);
				
		commonSecretHandler.decryptCommonSecret(aesKeyBytes, buffer, 
					ivOffset, AES_IV_LEN);
								
		byte res = Util.arrayCompare(decryptedPassword, (short) 0x00, buffer, ISO7816.OFFSET_CDATA, PASSWORD_SIZE);
        		
		if(res != 0x00) {
        	numPasswordTries++;
        	
        	if (numPasswordTries >= MAX_PASSWORD_TRIES) {
        		GPSystem.setCardContentState(Constants.APP_BLOCKED_MODE);
	        	ISOException.throwIt(SW_INCORRECT_PASSWORD_CARD_IS_BLOCKED);
        	}
               	
	        ISOException.throwIt(SW_INCORRECT_PASSWORD_FOR_CARD_AUTHENICATION);
        }
        else {
	        GPSystem.setCardContentState(Constants.APP_PERSONALIZED);
	        shaMessageDigest.doFinal(decryptedPassword, (short) 0x00, PASSWORD_SIZE, decryptedPasswordHash, (short) 0x00);
	        apduDataProtectionHandler.generateHmacKey(commonSecretHandler.getCommonSecret(), decryptedPasswordHash);
        }                     
    }         
}


