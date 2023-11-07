package tonwallet ;

import javacard.framework.*;
import javacard.framework.APDU;
import com.ftsafe.javacardx.btcmgr.CoinManager;
import static tonwallet.Constants.*;
import static tonwallet.ErrorCodes.*;

public class TonCryptoHandler {	
	public final static short PATH_BUFFER_MAX_SIZE = (short) 50;
	public final static short TMP_BUFFER_SIZE = (short) 512;
	public final static short TON_PUBLIC_KEY_SIZE = (short) 32;
	public final static short CHAIN_CODE_KEY_SIZE = (short) 32;
	public final static short TON_CHAIN_CODE_CONSTANT = (short) 65;
	
	public final static short KEY_SIZE = (short) 32;
	public final static short SIGNATURE_SIZE = (short) 64;
	public final static short PK_OFFSET = (short) 0x01;
	public final static short SIG_OFFSET = (short) 0x01;
	public final static short PATH_OFFSET = (short) 0x01;
   	

	// m/44'/396'/0'/0'/
	private static final byte[] HD_PATH_PREFIX = new byte[] {0x6D,0x2F,0x34,0x34,0x27,0x2F,0x33,0x39,0x36,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27,0x2F};
	private static final byte HD_PATH_SUFFIX = (byte) 0x27;

	
	// m/44'/396'/0'/0'/0'
	private static final byte[] ROOT_HD_PATH = new byte[] {0x6D,0x2F,0x34,0x34,0x27,0x2F,0x33,0x39,0x36,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27};
	private static final byte[] ROOT_HD_PATH_IN_LV = new byte[] {0x13, 0x6D,0x2F,0x34,0x34,0x27,0x2F,0x33,0x39,0x36,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27,0x2F,0x30,0x27};
	    	     
    private byte[] tmpBuffer;   
    private byte[] pathBuffer;
    
    private ApduDataProtectionHandler apduDataProtectionHandler;
    private PinHandler pinHandler;
    
    private static TonCryptoHandler tonCryptoHandler;
    
  
	public static TonCryptoHandler getInstance() {
		if (tonCryptoHandler == null)
			tonCryptoHandler = new TonCryptoHandler();
		return tonCryptoHandler;
	}
    
    private TonCryptoHandler () {				
		try {
            tmpBuffer = JCSystem.makeTransientByteArray(TMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
            tmpBuffer = new byte[TMP_BUFFER_SIZE];
		}
		
        pathBuffer = new byte[PATH_BUFFER_MAX_SIZE];
		
		Util.arrayCopyNonAtomic(HD_PATH_PREFIX, (short) 0x00, 
					pathBuffer, PATH_OFFSET, (short) HD_PATH_PREFIX.length); 
							
		apduDataProtectionHandler = ApduDataProtectionHandler.getInstance(); 
		pinHandler = PinHandler.getInstance();
    }
    
            
     /*
     This function returns the public key for given bip44 HD path.
     This HD path is a hex representation of string having a form m/44’/396’/0’/0’/ind’.
     Only 'ind' is changed for TON. 0 <= ind <= 2^31 - 1
     
     * cla: 0xB0
     * ins: 0xA0
     * p1: 0x00
     * p2: 0x00
     * Lc: length of hex representation of ind (max size for it is 10 bytes) 
     * data: hex representation of ind
     * Response data:  TON public key bytes (32 bytes)
     */
    
    public void getPublicKey(APDU apdu){
    	if (pinHandler.getNumPinFails() >= MAX_PIN_TRIES_NUM) {
	    	ISOException.throwIt(SW_PIN_TRIES_EXPIRED);
    	}
    	
        byte[] buffer = apdu.getBuffer();

        short numBytes = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
        short byteRead = apdu.setIncomingAndReceive();

        if (numBytes != byteRead || numBytes > MAX_IND_SIZE){
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
               
        //copy ind from buffer into path
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, 
					pathBuffer, (short) (PATH_OFFSET + HD_PATH_PREFIX.length), numBytes);
		short suffixOffset = (short)(PATH_OFFSET + HD_PATH_PREFIX.length + numBytes);
		// put final '
		pathBuffer[suffixOffset] = HD_PATH_SUFFIX;
		short pathLen = suffixOffset;
		
		short le = apdu.setOutgoing();       
        if (le != TON_PUBLIC_KEY_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
	    
        short ret = CoinManager.getCoinPubData(
			pathBuffer, PATH_OFFSET, pathLen,
			 buffer, (short) 0x00, buffer, TON_CHAIN_CODE_CONSTANT);
        
        if (ret != 0x00) {
           ISOException.throwIt(SW_GET_COIN_PUB_DATA_FAILED);
        }
                        
        apdu.setOutgoingLength(TON_PUBLIC_KEY_SIZE);      
        apdu.sendBytes(PK_OFFSET, TON_PUBLIC_KEY_SIZE);
    }
    
    /*
     This function retrieves public key from CoinManager for fixed bip32 HD path 
     m/44'/396'/0'/0'/0'.
     
     * cla: 0xB0
     * ins: 0xA7
     * p1: 0x00
     * p2: 0x00
     * Response data:  TON public key bytes (32 bytes)
     */
    public void getPublicKeyWithDefaultHDPath(APDU apdu){
    	if (pinHandler.getNumPinFails() >= MAX_PIN_TRIES_NUM) {
	    	ISOException.throwIt(SW_PIN_TRIES_EXPIRED);
    	}
    	
    	byte[] buf = apdu.getBuffer();
    	
    	short le = apdu.setOutgoing();       
        if (le != TON_PUBLIC_KEY_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        } 
        
        short ret = CoinManager.getCoinPubData(ROOT_HD_PATH, (short) 0x00, (short) ROOT_HD_PATH.length, 
				buf, (short) 0x00, buf, TON_CHAIN_CODE_CONSTANT);
        
        if (ret != 0x00) {
           ISOException.throwIt(SW_GET_COIN_PUB_DATA_FAILED);
        }
                       
        apdu.setOutgoingLength(TON_PUBLIC_KEY_SIZE);       
        apdu.sendBytes(PK_OFFSET, TON_PUBLIC_KEY_SIZE);
     }
    
    /**
     * This function signs the message from apdu buffer for given bip44 HD path.
      This HD path is a hex representation of string having a form m/44’/396’/0’/0’/ind’.
      
      !!!!Important note: here signature for now is supposed to have format that is produced by
       CoinManager: 0x41 + 64bytes of signature + some byte
      
     * cla: 0xB0
     * ins: 0xA3
     * p1: 0x00
     * p2: 0x00
     * Lc: total len of data 
     * Le: SIGNATURE_SIZE// 0x40
     * data: [messageLength (2 bytes) | message | indLength  (1 byte, > 0, <= 10) | ind | sault (32 bytes) 
     | hmac (32 bytes)]
     //example: 00 04 01 01 01 01 01 03 31 37 31 | sault | mac
     
     * Response data: [signature]
     */

    public void signShortMessage(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
    	
    	byte[] lens = apduDataProtectionHandler.verifyInputApduDataContainingDataForSigningAndPath(apdu);
     	        
        short dataOffset = ISO7816.OFFSET_CDATA;
        short dataLen = (short)(Util.getShort(lens, (short) 0x00) + 0x02);
        
        short indPathLenOffset = (short)(dataOffset + dataLen);
        short indPathLen = lens[0x02];
        short indPathOffset = (short)(indPathLenOffset + 0x01);
        
        //copy ind from buffer into path
        Util.arrayCopyNonAtomic(buffer, indPathOffset, 
					pathBuffer, (short) (PATH_OFFSET + HD_PATH_PREFIX.length), indPathLen);
		short suffixOffset = (short)(PATH_OFFSET + HD_PATH_PREFIX.length + indPathLen);
		
		pathBuffer[suffixOffset] = HD_PATH_SUFFIX;
		short pathLen = suffixOffset;
		pathBuffer[0] = (byte) pathLen;
		
		short le = apdu.setOutgoing();       
        if (le != SIGNATURE_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        } 
						       
        short result = CoinManager.signCoinDataED25519((short) 0x01, buffer, dataOffset, dataLen, 
					tmpBuffer, (short) 0x00,   pathBuffer, (short) 0x00, (short)(pathLen + 0x01));
                                       
        if (result != 0x00) {
           ISOException.throwIt(SW_SIGN_DATA_FAILED);
        }
                       
        apdu.setOutgoingLength(SIGNATURE_SIZE);
        apdu.sendBytesLong(tmpBuffer, SIG_OFFSET, SIGNATURE_SIZE);        
    }
    
     
     /*
      This function signs the message from apdu buffer for default bip32 HD path
      m/44'/396'/0'/0'/0'.
      
      !!!!Important note: here signature for now is supposed to have format that is produced by
       CoinManager: 0x40 + 64bytes of signature + some byte
      
     * cla: 0xB0
     * ins: 0xA5
     * p1: 0x00
     * p2: 0x00
     * lc: data length
     * Le: SIGNATURE_SIZE// 0x40
     * data: [messageLength (2bytes)| message | sault (32 bytes) 
     | hmac (32 bytes)] // like : 00 04 01 01 01 01 etc
     * Response data: [signature]
     */

    public void signShortMessageWithDefaultPath(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
    	
        short dataOffset = ISO7816.OFFSET_CDATA;       		
		short dataLen = (short)(apduDataProtectionHandler.verifyInputApduDataContainingDataForSigning(apdu) + 0x02);
							        
        short le = apdu.setOutgoing();
        if (le != SIGNATURE_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        short result = CoinManager.signCoinDataED25519((short) 0x01, buffer, dataOffset, dataLen, 
					tmpBuffer, (short) 0x00,  ROOT_HD_PATH_IN_LV, (short) 0x00, (short) ROOT_HD_PATH_IN_LV.length);
		        
        if (result != 0x00) {
           ISOException.throwIt(SW_SIGN_DATA_FAILED);
        }        
                
        apdu.setOutgoingLength(SIGNATURE_SIZE);
        apdu.sendBytesLong(tmpBuffer, SIG_OFFSET, SIGNATURE_SIZE);
    }       
}



