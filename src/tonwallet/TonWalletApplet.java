package tonwallet;

import javacard.framework.*;
import org.globalplatform.GPSystem;
import com.ftsafe.javacardx.btcmgr.CoinManager;
import static tonwallet.ErrorCodes.*;

public class TonWalletApplet extends Applet
{
	// code of CLA byte in the command APDU header
    private final static byte WALLET_APPLET_CLA = (byte) 0xB0;

    /****************************************
     * Instruction codes *
     ****************************************
     */
    //Personalization
    private static final byte INS_FINISH_PERS = (byte)0x90;
    private static final byte INS_SET_ENCRYPTED_PASSWORD_FOR_CARD_AUTHENTICATION = (byte)0x91;
    private static final byte INS_SET_ENCRYPTED_COMMON_SECRET  = (byte)0x94;
    private static final byte INS_SET_SERIAL_NUMBER  = (byte)0x96;
    
    //Waite for authentication mode
    private static final byte INS_VERIFY_PASSWORD = (byte)0x92; 
    private static final byte INS_GET_HASH_OF_ENCRYPTED_PASSWORD = (byte)0x93; 
    private static final byte INS_GET_HASH_OF_ENCRYPTED_COMMON_SECRET = (byte)0x95; 
       
    // Main mode
    private static final byte INS_GET_PUBLIC_KEY = (byte)0xA0;
    private static final byte INS_GET_PUBLIC_KEY_WITH_DEFAULT_HD_PATH  = (byte)0xA7;
    private static final byte INS_VERIFY_PIN = (byte)0xA2;
    private static final byte INS_SIGN_SHORT_MESSAGE = (byte)0xA3;
    private static final byte INS_SIGN_SHORT_MESSAGE_WITH_DEFAULT_PATH = (byte)0xA5;
        
    private static final byte INS_CHECK_KEY_HMAC_CONSISTENCY = (byte)0xB0;
    private static final byte INS_GET_KEY_INDEX_IN_STORAGE_AND_LEN = (byte)0xB1;
    private static final byte INS_GET_KEY_CHUNK = (byte)0xB2;
    private static final byte INS_CHECK_AVAILABLE_VOL_FOR_NEW_KEY = (byte)0xB3;
    private static final byte INS_ADD_KEY_CHUNK = (byte)0xB4;
    private static final byte INS_INITIATE_CHANGE_OF_KEY = (byte)0xB5;
    private static final byte INS_CHANGE_KEY_CHUNK = (byte)0xB6;
    private static final byte INS_INITIATE_DELETE_KEY = (byte)0xB7;
    
    private static final byte INS_GET_NUMBER_OF_KEYS = (byte)0xB8; 
    private static final byte INS_GET_FREE_STORAGE_SIZE = (byte)0xB9;
    private static final byte INS_GET_OCCUPIED_STORAGE_SIZE = (byte)0xBA;  
    private static final byte INS_GET_HMAC = (byte)0xBB;  
    private static final byte INS_RESET_KEYCHAIN = (byte)0xBC;  
    
    private static final byte INS_DELETE_KEY_CHUNK = (byte)0xBE;
    private static final byte INS_DELETE_KEY_RECORD = (byte)0xBF;
    private static final byte INS_GET_DELETE_KEY_CHUNK_NUM_OF_PACKETS =  (byte)0xE1;   
    private static final byte INS_GET_DELETE_KEY_RECORD_NUM_OF_PACKETS =  (byte)0xE2;   
    private static final byte INS_GET_DELETE_KEY_CHUNK_COUNTER =  (byte)0xE3;   
    private static final byte INS_GET_DELETE_KEY_RECORD_COUNTER =  (byte)0xE4;   
    
   
    private static final byte INS_GET_SAULT = (byte)0xBD;    
    private static final byte INS_GET_APP_INFO = (byte)0xC1;
    private static final byte INS_GET_SERIAL_NUMBER  = (byte)0xC2;
    
    private static final byte INS_ADD_RECOVERY_DATA_PART = (byte)0xD1;
    private static final byte INS_GET_RECOVERY_DATA_PART = (byte)0xD2;
    private static final byte INS_GET_RECOVERY_DATA_HASH = (byte)0xD3;
    private static final byte INS_GET_RECOVERY_DATA_LEN = (byte)0xD4;
    private static final byte INS_RESET_RECOVERY_DATA = (byte)0xD5;
    private static final byte INS_IS_RECOVERY_DATA_SET = (byte)0xD6;
    
    private TonCryptoHandler cryptoHandler;  
    private KeyChain keyChain;
    private CardAuthenticationHandler cardAuthenticationHandler;
    private PinHandler pinHandler;
    private CommonHandler commonHandler;
    private CommonSecretHandler commonSecretHandler;
    private RecoveryDataHandler recoveryDataHandler;
    private SerialNumberHandler serialNumberHandler;
      
    public TonWalletApplet(){
	   cryptoHandler = TonCryptoHandler.getInstance();
       keyChain = KeyChain.getInstance();
       cardAuthenticationHandler = CardAuthenticationHandler.getInstance();
       pinHandler = PinHandler.getInstance();
       commonHandler = CommonHandler.getInstance();
       commonSecretHandler = CommonSecretHandler.getInstance();
       recoveryDataHandler = RecoveryDataHandler.getInstance();
       serialNumberHandler = SerialNumberHandler.getInstance();
    }

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new TonWalletApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			short ret = CoinManager.setCurve(CoinManager.CURVE_ED25519); 
	    
			if (ret != CoinManager.SEC_TRUE) {
				ISOException.throwIt(SW_SET_CURVE_FAILED);
			}
			return;
		}
            
        byte[] buffer = apdu.getBuffer();
        byte cla = (byte) (buffer[ISO7816.OFFSET_CLA] & 0xFF);
        byte ins = (byte) (buffer[ISO7816.OFFSET_INS] & 0xFF);

        // check SELECT APDU command
        if ((cla == 0x00) && (ins == (byte) 0xA4)) {
	        return;
        }
            
        if (cla != WALLET_APPLET_CLA) {
	        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
            
        switch (GPSystem.getCardContentState()) {
            case Constants.APP_INSTALLED: {
                switch (ins) {
                    case INS_GET_APP_INFO:
                        commonHandler.getAppInfo(apdu);
                        break;					
                    case INS_SET_ENCRYPTED_PASSWORD_FOR_CARD_AUTHENTICATION:
                    	cardAuthenticationHandler.setEncryptedPassword(apdu);
                    	break;
                    case INS_GET_HASH_OF_ENCRYPTED_PASSWORD:
						cardAuthenticationHandler.getHashOfEncryptedPassword(apdu);                           
						break;	
					case INS_SET_ENCRYPTED_COMMON_SECRET:
						commonSecretHandler.setEncryptedCommonSecret(apdu);
						break;
					case INS_GET_HASH_OF_ENCRYPTED_COMMON_SECRET:
						commonSecretHandler.getHashOfEncryptedCommonSecret(apdu);
						break;
					case INS_SET_SERIAL_NUMBER:
						serialNumberHandler.setSerialNumber(apdu);
						break;
					case INS_GET_SERIAL_NUMBER:
						serialNumberHandler.getSerialNumber(apdu);
						break;
                    case INS_FINISH_PERS:
                        commonHandler.finishPers(apdu);
                        break;					
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                break;
            }
            case Constants.APP_WAITE_AUTHORIZATION_MODE: {
            	switch (ins) {
					case INS_GET_APP_INFO:
                        commonHandler.getAppInfo(apdu);
                        break; 
                    case INS_GET_HASH_OF_ENCRYPTED_PASSWORD:
						cardAuthenticationHandler.getHashOfEncryptedPassword(apdu);                           
						break;
					case INS_GET_HASH_OF_ENCRYPTED_COMMON_SECRET:
						commonSecretHandler.getHashOfEncryptedCommonSecret(apdu);
						break;
					case INS_GET_SERIAL_NUMBER:
						serialNumberHandler.getSerialNumber(apdu);
						break;
                    case INS_VERIFY_PASSWORD:
                    	cardAuthenticationHandler.verifyPassword(apdu);
                    	break;  
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); 
            	} 
            	break;
            } 
            case Constants.APP_BLOCKED_MODE: {
            	switch (ins) {
					case INS_GET_APP_INFO:
                        commonHandler.getAppInfo(apdu);
                        break;
                    case INS_GET_SERIAL_NUMBER:
						serialNumberHandler.getSerialNumber(apdu);
						break;                        
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); 
            	} 
            	break;
            }           
            case Constants.APP_PERSONALIZED: {
                switch (ins) {
                	 /*Commands for keychain */
                    case INS_GET_KEY_INDEX_IN_STORAGE_AND_LEN:
                        keyChain.getKeyIndexInStorageAndLen(apdu);
                        break;    
                    case INS_GET_KEY_CHUNK:
                        keyChain.getKeyChunk(apdu);
                        break; 
                    case INS_CHECK_AVAILABLE_VOL_FOR_NEW_KEY: 
                    	keyChain.checkAvailabilityOfStorageFreeVolumeForNewKey(apdu);
                        break;
                    case INS_ADD_KEY_CHUNK:
                        keyChain.addKeyChunk(apdu);
                        break;
                    case INS_INITIATE_CHANGE_OF_KEY:
                        keyChain.initiateChangeOfKey(apdu);
                        break;    
                    case INS_CHANGE_KEY_CHUNK:
                        keyChain.changeKeyChunk(apdu);
                        break;
                    case INS_INITIATE_DELETE_KEY:
                        keyChain.initiateDeleteOfKey(apdu);
                        break;
                    case INS_GET_NUMBER_OF_KEYS:
                        keyChain.getNumberOfKeys(apdu);
                        break; 
					case INS_GET_FREE_STORAGE_SIZE:
						keyChain.getFreeStorageSize(apdu);
						break; 
					case INS_GET_OCCUPIED_STORAGE_SIZE:	
						keyChain.getOccupiedStorageSize(apdu);
						break;
					case INS_GET_HMAC:
						keyChain.getHmac(apdu);
						break;
					case INS_RESET_KEYCHAIN:
						keyChain.reset(apdu);
						break;
					case INS_CHECK_KEY_HMAC_CONSISTENCY:
						keyChain.checkKeyHmacConsistency(apdu);
						break;	
					case INS_GET_SAULT:
						SaultHandler.getInstance().getSault(apdu);
						break;
						/**/
                                             
                    /* Commands to handle transactions signing */          
                    case INS_GET_PUBLIC_KEY:
                        cryptoHandler.getPublicKey(apdu);
                        break;
                    case INS_GET_PUBLIC_KEY_WITH_DEFAULT_HD_PATH:
                        cryptoHandler.getPublicKeyWithDefaultHDPath(apdu);
                        break;
                    case INS_SIGN_SHORT_MESSAGE:
                    	cryptoHandler.signShortMessage(apdu);
                        break;
                    case INS_SIGN_SHORT_MESSAGE_WITH_DEFAULT_PATH:
                    	cryptoHandler.signShortMessageWithDefaultPath(apdu);
                        break;
                    case INS_VERIFY_PIN:
                    	pinHandler.checkPin(apdu);
                        break;	
                        
                    /* Commands to handle RecoveryDataHandler */          
                    case INS_ADD_RECOVERY_DATA_PART:
                        recoveryDataHandler.addRecoveryDataPart(apdu);
                        break;
                    case INS_GET_RECOVERY_DATA_PART:
                        recoveryDataHandler.getRecoveryDataPart(apdu);
                        break;
                    case INS_RESET_RECOVERY_DATA:
                        recoveryDataHandler.resetRecoveryData(apdu);
                        break;
                    case INS_GET_RECOVERY_DATA_HASH:
                    	recoveryDataHandler.getHashOfRecoveryData(apdu);
                        break;
                    case INS_GET_RECOVERY_DATA_LEN:
                    	recoveryDataHandler.getRecoveryDataLen(apdu);
                        break;
                    case INS_IS_RECOVERY_DATA_SET:
                    	recoveryDataHandler.isRecoveryDataSet(apdu);
                        break;

                    /* Common commands */
                    case INS_GET_SERIAL_NUMBER:
						serialNumberHandler.getSerialNumber(apdu);
						break;                        					
                    case INS_GET_APP_INFO:
                        commonHandler.getAppInfo(apdu);
                        break;
                                         
                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
                break;
            }
            case Constants.APP_DELETE_KEY_FROM_KEYCHAIN_MODE: {
            	switch (ins) {
            		case INS_GET_KEY_INDEX_IN_STORAGE_AND_LEN:
                        keyChain.getKeyIndexInStorageAndLen(apdu);
                        break;    
                    case INS_GET_KEY_CHUNK:
                        keyChain.getKeyChunk(apdu);
                        break;
                    case INS_GET_DELETE_KEY_CHUNK_COUNTER:
                        keyChain.getDeleteKeyChunkCounter(apdu);
                        break;
                    case INS_GET_DELETE_KEY_RECORD_COUNTER:
                        keyChain.getDeleteKeyRecordCounter(apdu);
                        break;
                    case INS_GET_DELETE_KEY_CHUNK_NUM_OF_PACKETS:
                        keyChain.getDeleteKeyChunkNumOfPackets(apdu);
                        break;
                    case INS_GET_DELETE_KEY_RECORD_NUM_OF_PACKETS:
                        keyChain.getDeleteKeyRecordNumOfPackets(apdu);
                        break;
            		case INS_DELETE_KEY_CHUNK:
                        keyChain.deleteKeyChunk(apdu);
                        break;
                    case INS_DELETE_KEY_RECORD:
                        keyChain.deleteKeyRecord(apdu);
                        break;
                    case INS_GET_NUMBER_OF_KEYS:
                        keyChain.getNumberOfKeys(apdu);
                        break; 
					case INS_GET_FREE_STORAGE_SIZE:
						keyChain.getFreeStorageSize(apdu);
						break; 
					case INS_GET_OCCUPIED_STORAGE_SIZE:	
						keyChain.getOccupiedStorageSize(apdu);
						break;
					case INS_GET_HMAC:
						keyChain.getHmac(apdu);
						break;
					case INS_RESET_KEYCHAIN:
						keyChain.reset(apdu);
						break;
					case INS_CHECK_KEY_HMAC_CONSISTENCY:
						keyChain.checkKeyHmacConsistency(apdu);
						break;	
					case INS_GET_SAULT:
						SaultHandler.getInstance().getSault(apdu);
						break;    
                    
                    
                    /* Commands to handle transactions signing */          
                    case INS_GET_PUBLIC_KEY:
                        cryptoHandler.getPublicKey(apdu);
                        break;
                    case INS_GET_PUBLIC_KEY_WITH_DEFAULT_HD_PATH:
                        cryptoHandler.getPublicKeyWithDefaultHDPath(apdu);
                        break;
                    case INS_SIGN_SHORT_MESSAGE:
                    	cryptoHandler.signShortMessage(apdu);
                        break;
                    case INS_SIGN_SHORT_MESSAGE_WITH_DEFAULT_PATH:
                    	cryptoHandler.signShortMessageWithDefaultPath(apdu);
                        break;
                    case INS_VERIFY_PIN:
                    	pinHandler.checkPin(apdu);
                        break;
                        
                    /* Commands to handle RecoveryDataHandler */          
                    case INS_ADD_RECOVERY_DATA_PART:
                        recoveryDataHandler.addRecoveryDataPart(apdu);
                        break;
                    case INS_GET_RECOVERY_DATA_PART:
                        recoveryDataHandler.getRecoveryDataPart(apdu);
                        break;
                    case INS_RESET_RECOVERY_DATA:
                        recoveryDataHandler.resetRecoveryData(apdu);
                        break;
                    case INS_GET_RECOVERY_DATA_HASH:
                    	recoveryDataHandler.getHashOfRecoveryData(apdu);
                        break;	
                    case INS_GET_RECOVERY_DATA_LEN:
                    	recoveryDataHandler.getRecoveryDataLen(apdu);
                        break;
                    case INS_IS_RECOVERY_DATA_SET:
                    	recoveryDataHandler.isRecoveryDataSet(apdu);
                        break;

                    /* Common commands */
                    case INS_GET_SERIAL_NUMBER:
						serialNumberHandler.getSerialNumber(apdu);
						break;                       					
                    case INS_GET_APP_INFO:
                        commonHandler.getAppInfo(apdu);
                        break;    
                        
            		default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);                                      
            	}
            	break;
            }           
            default:
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
	}
}

