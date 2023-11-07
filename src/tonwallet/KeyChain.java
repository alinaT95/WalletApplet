package tonwallet ;

import javacard.framework.*;
import org.globalplatform.GPSystem;
import static tonwallet.Constants.*;
import static tonwallet.ErrorCodes.*;

public class KeyChain  
{	
	public static final short KEY_CHAIN_SIZE = 32767;
	public static final short KEY_RECORDS_SIZE = 1023;
	public static final short MAX_KEY_SIZE = 8192;
	public final static byte START_OF_TRANSMISSION = 0x00;
	public final static byte END_OF_TRANSMISSION = 0x02;
	public static final short PACKET_SIZE_FOR_DELETE_KEY_CHUNK = (short)128;
	public static final short PACKET_SIZE_FOR_DELETE_KEY_RECORD = (short)12;
	
	private short[] keyLens; 
	private short[] keyOffsets; 
	private byte[] keyMacs; 
	private byte[] keyStore;
	private byte[] keyTmpBuffer;
	
	private short numberOfStoredKeys;	// invariant : numberOfStoredKeys <= KEY_RECORDS_SIZE
	private short newKeySize;
	private short totalIncomingBytesOfNewKey;
	private short indOfKeyToChange;
	
	private short payloadLen;
	
	//for delete
	private short indOfKeyToDelete;
	private short keyOffsetToDelete;
	private short keyLenToDelete;
	private short offsetOfNextKey;
	private short totalLen;
	private short deleteKeyChunkCounter = 0;
	private short deleteKeyChunkNumOfPackets = 0;
	private short tailLenForDeleteKeyChunk = 0;
	private short deleteKeyChunkIsDone = 0;
	private short deleteKeyRecordCounter = 0;
	private short tailLenForDeleteKeyRecord = 0;
	private short deleteKeyRecordNumOfPackets = 0;
	private short deleteKeyRecordIsDone  = 0;
	
	private ApduDataProtectionHandler apduDataProtectionHandler;
	
	private static KeyChain keyChain;
	
	public static KeyChain getInstance() {
		if (keyChain == null)
			keyChain = new KeyChain();
		return keyChain;
	}
	
	private KeyChain() {
		keyStore = new byte[KEY_CHAIN_SIZE];
		keyLens = new short[KEY_RECORDS_SIZE];
		keyOffsets = new short[KEY_RECORDS_SIZE];
		keyMacs = new byte[(short)(KEY_RECORDS_SIZE * HMAC_SIG_SIZE)];		
		keyTmpBuffer = new byte[MAX_KEY_SIZE];
		apduDataProtectionHandler = ApduDataProtectionHandler.getInstance();
	}
	
	private short findKeyRecordIndex(byte[] mac, short offset) {
		if (offset < 0x00) {
			ISOException.throwIt(SW_INCORRECT_OFFSET);
		}
		if (mac == null || (short)(mac.length - offset) < HMAC_SIG_SIZE) {
			ISOException.throwIt(SW_INTERNAL_BUFFER_IS_NULL_OR_TOO_SMALL);
		}
		
		for(short i = 0x00; i < numberOfStoredKeys; i++) {
			byte res = Util.arrayCompare(keyMacs, (short) (i * HMAC_SIG_SIZE), 
					mac, offset, HMAC_SIG_SIZE);
			if (res == 0x00) {
				return i;
			}
		}
		return -1;
	}
	
	private short getOccupiedStorageSize() {
		short size = 0x00;
		for(short i = 0x00; i < numberOfStoredKeys; i++){
			size = (short)(size + keyLens[i]);
		}
		return size;
	}
	
	public void reset(APDU apdu) {
		payloadLen = SAULT_SIZE;
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		numberOfStoredKeys = 0x00;
		newKeySize = 0x00;
		totalIncomingBytesOfNewKey = 0x00;
		deleteKeyChunkIsDone = 0x00;
		deleteKeyRecordIsDone = 0x00;
		deleteKeyChunkNumOfPackets = 0x00;
		deleteKeyRecordNumOfPackets = 0x00;
		deleteKeyChunkCounter = 0x00;
		deleteKeyRecordCounter = 0x00;
		tailLenForDeleteKeyChunk = 0x00;
		tailLenForDeleteKeyRecord = 0x00;
		indOfKeyToChange = -1;
		for(short i = 0x00; i < KEY_RECORDS_SIZE; i++) {
			resetKeyOffsetAndlen(i);
		}		
		Util.arrayFillNonAtomic(keyStore, (short) 0x00, (short) keyStore.length, (byte) 0x00);
		Util.arrayFillNonAtomic(keyTmpBuffer, (short) 0x00, (short) keyTmpBuffer.length, (byte) 0x00);
		Util.arrayFillNonAtomic(keyMacs, (short) 0x00, (short) keyMacs.length, (byte) 0x00);
		GPSystem.setCardContentState(Constants.APP_PERSONALIZED);
	}
		
	public void getFreeStorageSize(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		payloadLen = SAULT_SIZE;
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short le = apdu.setOutgoing();       
        if (le != (short) 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, (short)(KEY_CHAIN_SIZE - getOccupiedStorageSize()));
		apdu.sendBytes((short) 0x00, (short) 0x02);
	}
	
	public void getOccupiedStorageSize(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		payloadLen = SAULT_SIZE;		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short le = apdu.setOutgoing();       
        if (le != (short) 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, getOccupiedStorageSize());
		apdu.sendBytes((short) 0x00, (short) 0x02);
		
	}
	
	public void getHmac(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		
		payloadLen = (short)(0x02 + SAULT_SIZE);
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		
		short le = apdu.setOutgoing();       
        if (le != (short)(HMAC_SIG_SIZE + 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
		
		short ind = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        
        if(ind < 0x00 || ind >= numberOfStoredKeys) {
	        ISOException.throwIt(SW_INCORRECT_KEY_INDEX);
        }
                       
        Util.arrayCopyNonAtomic(keyMacs, (short) (ind * HMAC_SIG_SIZE), 
					buffer, (short) 0x00, HMAC_SIG_SIZE); 
		Util.setShort(buffer, HMAC_SIG_SIZE, keyLens[ind]);
        
        apdu.setOutgoingLength((short)(HMAC_SIG_SIZE + 2));  
		apdu.sendBytes((short) 0x00, (short)(HMAC_SIG_SIZE + 2));
	}
	
	public void checkKeyHmacConsistency(APDU apdu) {
		byte[] buffer = apdu.getBuffer();	
		payloadLen = (short)(HMAC_SIG_SIZE + SAULT_SIZE);
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short ind = findKeyRecordIndex(buffer, ISO7816.OFFSET_CDATA);	
		if(ind < 0x00 || ind >= numberOfStoredKeys) {
	        ISOException.throwIt(SW_INCORRECT_KEY_INDEX);
        }
		apduDataProtectionHandler.verifyMacOfKey(keyStore, keyOffsets[ind], keyLens[ind], 
				buffer, ISO7816.OFFSET_CDATA);
	}
	
	public void getKeyIndexInStorageAndLen(APDU apdu) {
		byte[] buffer = apdu.getBuffer();	
		payloadLen = (short)(HMAC_SIG_SIZE + SAULT_SIZE);
		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		
		short le = apdu.setOutgoing();       
        if (le != (short) 0x04) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }       
		short ind = findKeyRecordIndex(buffer, ISO7816.OFFSET_CDATA);		
		if (ind == -1) {
			ISOException.throwIt(SW_INCORRECT_KEY_INDEX);
		}		
		apdu.setOutgoingLength((short) 0x04);		
		Util.setShort(buffer, (short) 0x00, ind);
		Util.setShort(buffer, (short) 0x02, keyLens[ind]);		
		apdu.sendBytes((short) 0x00, (short) 0x04);
	}
	
	public void getKeyChunk(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		payloadLen = (short)(0x04 + SAULT_SIZE);
    	
    	apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
    	short ind = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
    	
    	if(ind < 0x00 || ind >= numberOfStoredKeys) {
	        ISOException.throwIt(SW_INCORRECT_KEY_INDEX);
        }
        
        short startPos = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA + 0x02));
        short le = apdu.setOutgoing();
        short endPosOfKey = (short) (keyOffsets[ind] + keyLens[ind] - 1);
        short keyStoreOffset = (short)(keyOffsets[ind] + startPos);               
        if((startPos < 0x00) || (le <= 0x00) || (keyStoreOffset < 0) 
			|| (keyStoreOffset > endPosOfKey)
			|| ((short)(keyStoreOffset + le) > (short)(endPosOfKey + 1))) {
			ISOException.throwIt(SW_INCORRECT_KEY_CHUNK_START_OR_LEN);
		}
		
		apdu.setOutgoingLength(le);   
		apdu.sendBytesLong(keyStore, keyStoreOffset, le);         
	}
	
	public void initiateDeleteOfKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
        payloadLen = (short)(0x02 + SAULT_SIZE);		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
        indOfKeyToDelete = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        if (indOfKeyToDelete < 0x00 || indOfKeyToDelete >= numberOfStoredKeys) {
        	indOfKeyToDelete = (short) -1;
	        ISOException.throwIt(SW_INCORRECT_KEY_INDEX);
        }
                
        short le = apdu.setOutgoing();
		if (le != (short) 0x02) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		deleteKeyChunkIsDone = 0x00;
		deleteKeyRecordIsDone = 0x00;
		deleteKeyChunkNumOfPackets = 0x00;
		deleteKeyRecordNumOfPackets = 0x00;
		deleteKeyChunkCounter = 0x00;
		deleteKeyRecordCounter = 0x00;
		tailLenForDeleteKeyChunk = 0x00;
		tailLenForDeleteKeyRecord = 0x00;
		
		if (indOfKeyToDelete < (short)(numberOfStoredKeys - 0x01)) {
			keyOffsetToDelete = keyOffsets[indOfKeyToDelete];
			keyLenToDelete = keyLens[indOfKeyToDelete];
			offsetOfNextKey = keyOffsets[indOfKeyToDelete + 0x01];
			totalLen = getOccupiedStorageSize();
					
			deleteKeyChunkNumOfPackets = (short)((short)(totalLen - offsetOfNextKey) / PACKET_SIZE_FOR_DELETE_KEY_CHUNK);
			tailLenForDeleteKeyChunk = (short)((short)(totalLen - offsetOfNextKey) % PACKET_SIZE_FOR_DELETE_KEY_CHUNK);
			
			deleteKeyRecordNumOfPackets = (short)((numberOfStoredKeys - indOfKeyToDelete - 1) / PACKET_SIZE_FOR_DELETE_KEY_RECORD);
			tailLenForDeleteKeyRecord = (short)((numberOfStoredKeys - indOfKeyToDelete - 1) % PACKET_SIZE_FOR_DELETE_KEY_RECORD);
				
		}
		
		GPSystem.setCardContentState(Constants.APP_DELETE_KEY_FROM_KEYCHAIN_MODE);
		apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, keyLenToDelete);
		apdu.sendBytes((short) 0x00, (short) 0x02);
	}
	
	public void getDeleteKeyChunkCounter(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		payloadLen = SAULT_SIZE;		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short le = apdu.setOutgoing();       
        if (le != (short) 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, deleteKeyChunkCounter);
		apdu.sendBytes((short) 0x00, (short) 0x02);	
	}
	
	public void getDeleteKeyChunkNumOfPackets(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		payloadLen = SAULT_SIZE;		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short le = apdu.setOutgoing();       
        if (le != (short) 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, deleteKeyChunkNumOfPackets);
		apdu.sendBytes((short) 0x00, (short) 0x02);	
	}
	
	public void getDeleteKeyRecordCounter(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		payloadLen = SAULT_SIZE;		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short le = apdu.setOutgoing();       
        if (le != (short) 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, deleteKeyRecordCounter);
		apdu.sendBytes((short) 0x00, (short) 0x02);	
	}
	
	public void getDeleteKeyRecordNumOfPackets(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		payloadLen = SAULT_SIZE;		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short le = apdu.setOutgoing();       
        if (le != (short) 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, deleteKeyRecordNumOfPackets);
		apdu.sendBytes((short) 0x00, (short) 0x02);	
	}
	
	public void deleteKeyChunk(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		payloadLen = SAULT_SIZE;		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short le = apdu.setOutgoing();
		if (le != (short) 0x01) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		if ((deleteKeyChunkIsDone == 0x00) && (indOfKeyToDelete == (short)(numberOfStoredKeys - 0x01))) {
			JCSystem.beginTransaction();
			Util.arrayFillNonAtomic(keyStore, keyOffsets[indOfKeyToDelete], keyLens[indOfKeyToDelete], (byte) 0x00);
			deleteKeyChunkIsDone = 0x01;
			JCSystem.commitTransaction();
		}
		if (deleteKeyChunkIsDone == 0x00){
			JCSystem.beginTransaction();
			short start, end;
			if (deleteKeyChunkCounter < deleteKeyChunkNumOfPackets)	{
				start = (short)(deleteKeyChunkCounter * PACKET_SIZE_FOR_DELETE_KEY_CHUNK);
				end = (short)(start + PACKET_SIZE_FOR_DELETE_KEY_CHUNK);
			}
			else {
				start = (short)(deleteKeyChunkNumOfPackets * PACKET_SIZE_FOR_DELETE_KEY_CHUNK);
				end = (short)(start + tailLenForDeleteKeyChunk);
			}
			for(short i = start; i < end; i++) {
				keyStore[keyOffsetToDelete + i] = keyStore[offsetOfNextKey + i];
			}
			if (deleteKeyChunkCounter == deleteKeyChunkNumOfPackets)	 {
				deleteKeyChunkIsDone = 0x01;	
			}
			else {
				deleteKeyChunkCounter++;
			}
			JCSystem.commitTransaction();
		}
		apdu.setOutgoingLength((short) 0x01);
		buffer[0x00] = (byte) deleteKeyChunkIsDone;
		apdu.sendBytes((short) 0x00, (short) 0x01);
	}
	
	public void deleteKeyRecord(APDU apdu) {
		if (deleteKeyChunkIsDone != 0x01) {
			ISOException.throwIt(SW_DELETE_KEY_CHUNK_IS_NOT_FINISHED);
		}
		byte[] buffer = apdu.getBuffer();
		payloadLen = SAULT_SIZE;		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
		short le = apdu.setOutgoing();
		if (le != (short) 0x01) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		if ((deleteKeyRecordIsDone == 0x00) && (indOfKeyToDelete == (short)(numberOfStoredKeys - 0x01))) {
			JCSystem.beginTransaction();
			resetKeyRecord(indOfKeyToDelete);
			deleteKeyRecordIsDone = 0x01;
			numberOfStoredKeys--;
			GPSystem.setCardContentState(Constants.APP_PERSONALIZED);
			JCSystem.commitTransaction();			
		}
		if (deleteKeyRecordIsDone == 0x00){
			JCSystem.beginTransaction();
			short start, end;
			if (deleteKeyRecordCounter < deleteKeyRecordNumOfPackets)	 {
				start = (short)(indOfKeyToDelete + 0x01 + deleteKeyRecordCounter * PACKET_SIZE_FOR_DELETE_KEY_RECORD);
				end = (short)(start + PACKET_SIZE_FOR_DELETE_KEY_RECORD);
			}
			else {
				start = (short)(indOfKeyToDelete + 0x01 + deleteKeyRecordNumOfPackets * PACKET_SIZE_FOR_DELETE_KEY_RECORD);
				end = (short)(start + tailLenForDeleteKeyRecord);
			}
			for(short i = start; i < end; i++) {
				short newOffset = (short)(keyOffsets[i] - keyLenToDelete);
				setKeyRecord((short)(i - 0x01), newOffset, keyLens[i], keyMacs, (short) (i * HMAC_SIG_SIZE));
			}						
			if (deleteKeyRecordCounter == deleteKeyRecordNumOfPackets)	 {
				deleteKeyRecordIsDone = 0x01;	
				numberOfStoredKeys--;
				GPSystem.setCardContentState(Constants.APP_PERSONALIZED);	
			}
			else {
				deleteKeyRecordCounter++;
			}
			JCSystem.commitTransaction();
		}
		apdu.setOutgoingLength((short) 0x01);
		buffer[0x00] = (byte) deleteKeyRecordIsDone;
		apdu.sendBytes((short) 0x00, (short) 0x01);
	}
	
	public void getNumberOfKeys(APDU apdu) {
		byte[] buffer = apdu.getBuffer();	
		payloadLen = SAULT_SIZE;
    	apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);	
    	
		short le = apdu.setOutgoing();       
        if (le != (short) 0x02) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        apdu.setOutgoingLength((short) 0x02);
		Util.setShort(buffer, (short) 0x00, numberOfStoredKeys);
		apdu.sendBytes((short) 0x00, (short) 0x02);
	}
	
	public void checkAvailabilityOfStorageFreeVolumeForNewKey(APDU apdu) {
		if (numberOfStoredKeys == KEY_RECORDS_SIZE)	{
			ISOException.throwIt(SW_MAX_KEYS_NUMBER_EXCEEDED);
		}	
		byte[] buffer = apdu.getBuffer();				
        payloadLen = (short)(0x02 + SAULT_SIZE);
        newKeySize = 0x00;
        totalIncomingBytesOfNewKey = 0x00;
        apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);	
                
        short volForNewKey = Util.getShort(buffer, ISO7816.OFFSET_CDATA);        
        if (volForNewKey <= 0 || volForNewKey > MAX_KEY_SIZE) {
	        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        short freeVol = (short)(KEY_CHAIN_SIZE - getOccupiedStorageSize());
        if (volForNewKey > freeVol) {     	       	
	        ISOException.throwIt(SW_NOT_ENOUGH_SPACE);
        }
        
        newKeySize = volForNewKey;       
	}
	
	public void addKeyChunk(APDU apdu) {	
		if (numberOfStoredKeys == KEY_RECORDS_SIZE)	{
			ISOException.throwIt(SW_MAX_KEYS_NUMBER_EXCEEDED);
		}
		if (newKeySize <= 0x00) {
			ISOException.throwIt(SW_KEY_SIZE_UNKNOWN);
		}
		
        byte[] buffer = apdu.getBuffer();                
        byte statusOfTransmission = buffer[ISO7816.OFFSET_P1];
        
        if (statusOfTransmission == END_OF_TRANSMISSION) { //end of transmission
        	if (totalIncomingBytesOfNewKey != newKeySize) {
	        	ISOException.throwIt(SW_KEY_LEN_INCORRECT);
        	}
        	
        	payloadLen = (short)(HMAC_SIG_SIZE + SAULT_SIZE);
        	
        	apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
        	
        	short le = apdu.setOutgoing();
			if (le != (short) 0x02) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			apduDataProtectionHandler.verifyMacOfKey(keyTmpBuffer, (short) 0x00, newKeySize, 
				buffer, ISO7816.OFFSET_CDATA);
			
			short ind = findKeyRecordIndex(buffer, ISO7816.OFFSET_CDATA);
			
			if (ind >= 0x00){
				ISOException.throwIt(SW_HMAC_EXISTS);
			}
			
			Util.arrayCopyNonAtomic(keyTmpBuffer, (short) 0x00, keyStore, getOccupiedStorageSize(), newKeySize);
			JCSystem.beginTransaction();
			setKeyRecord(numberOfStoredKeys, getOccupiedStorageSize(), newKeySize, buffer, ISO7816.OFFSET_CDATA);
			numberOfStoredKeys++;
			JCSystem.commitTransaction();
							
			newKeySize = 0x00;
			totalIncomingBytesOfNewKey = 0x00;
				
			apdu.setOutgoingLength((short) 0x02);
			Util.setShort(buffer, (short) 0x00, numberOfStoredKeys);
			apdu.sendBytes((short) 0x00, (short) 0x02);
        }
        else { // not end of transmission
        	short lenOfKeyChunk = apduDataProtectionHandler.verifyInputApduDataContainingKeyChunk(apdu);
						
			if (statusOfTransmission == 0x00) { // start of key chunks Transmission
        		totalIncomingBytesOfNewKey = 0x00;
        	}
        	
			short freeVol = (short)(KEY_CHAIN_SIZE - getOccupiedStorageSize());
        	short newLen = (short)(totalIncomingBytesOfNewKey + lenOfKeyChunk);
        	if(newLen > freeVol|| newLen > newKeySize) {
				ISOException.throwIt(SW_INCORRECT_KEY_CHUNK_LEN);
			}
						        	                       	
			Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + 0x01), 
					keyTmpBuffer, totalIncomingBytesOfNewKey, lenOfKeyChunk); 
											        		        
	        totalIncomingBytesOfNewKey = newLen;
        }
	}
	
	public void initiateChangeOfKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
        payloadLen = (short)(0x02 + SAULT_SIZE);		 	
		apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
        indOfKeyToChange = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        if (indOfKeyToChange < 0x00 || indOfKeyToChange >= numberOfStoredKeys) {
        	indOfKeyToChange = (short) -1;
	        ISOException.throwIt(SW_INCORRECT_KEY_INDEX);
        }
	}
	
	public void changeKeyChunk(APDU apdu) {
		if (indOfKeyToChange == (short) -1) {
	        ISOException.throwIt(SW_INCORRECT_KEY_INDEX_TO_CHANGE);
        }
        
        byte[] buffer = apdu.getBuffer();                
        byte statusOfTransmission = buffer[ISO7816.OFFSET_P1];
        
        if (statusOfTransmission == END_OF_TRANSMISSION) { //end of transmission
        	if (totalIncomingBytesOfNewKey != keyLens[indOfKeyToChange]) {
	        	ISOException.throwIt(SW_KEY_LEN_INCORRECT);
        	}
        	
        	payloadLen = (short)(HMAC_SIG_SIZE + SAULT_SIZE);
        	
        	apduDataProtectionHandler.verifyInputApduData(apdu, payloadLen);
        	
        	short le = apdu.setOutgoing();
			if (le != (short) 0x02) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			
			apduDataProtectionHandler.verifyMacOfKey(keyTmpBuffer, (short) 0x00, keyLens[indOfKeyToChange], 
				buffer, ISO7816.OFFSET_CDATA);
        					
			short ind = findKeyRecordIndex(buffer, ISO7816.OFFSET_CDATA);			
			if (ind >= 0x00) {
				ISOException.throwIt(SW_HMAC_EXISTS);
			}
			
			Util.arrayCopyNonAtomic(keyTmpBuffer, (short) 0x00, 
				keyStore, keyOffsets[indOfKeyToChange], keyLens[indOfKeyToChange]);
			JCSystem.beginTransaction();
			setMac(indOfKeyToChange, buffer, ISO7816.OFFSET_CDATA);	
			indOfKeyToChange = -1;
			JCSystem.commitTransaction();
						
			totalIncomingBytesOfNewKey = 0x00;
										
			apdu.setOutgoingLength((short) 0x02);
			Util.setShort(buffer, (short) 0x00, numberOfStoredKeys);
			apdu.sendBytes((short) 0x00, (short) 0x02);
        }
        else { // not end of transmission
	        short lenOfKeyChunk = apduDataProtectionHandler.verifyInputApduDataContainingKeyChunk(apdu);
			
			if (statusOfTransmission == 0x00) { // start of key chunks Transmission
        		totalIncomingBytesOfNewKey = 0x00;
        	}
        	      	
        	short newLen = (short)(totalIncomingBytesOfNewKey + lenOfKeyChunk);
        	if(newLen > keyLens[indOfKeyToChange]) {
				ISOException.throwIt(SW_INCORRECT_KEY_CHUNK_LEN);
			} 
			
			Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + 0x01), 
					keyTmpBuffer, totalIncomingBytesOfNewKey, lenOfKeyChunk);  
						        	        
	        totalIncomingBytesOfNewKey = newLen;
        }
	}
	
	//===================== former keyRecord methods ==============
	
	private void resetKeyOffsetAndlen(short ind) {
		keyOffsets[ind] = 0x00;
		keyLens[ind] = 0x00;	
	}
	
	private void resetKeyRecord(short ind) {
		keyOffsets[ind] = 0x00;
		keyLens[ind] = 0x00;
		Util.arrayFillNonAtomic(keyMacs, (short) (ind * HMAC_SIG_SIZE), HMAC_SIG_SIZE, (byte) 0x00);	
	}
	
	private void setKeyRecord(short ind, short keyOffset, short keyLen, byte [] mac, short macOffset) {
		keyOffsets[ind] = keyOffset;
		keyLens[ind] = keyLen;
		setMac(ind, mac, macOffset);
	}
	
	private void setMac(short ind, byte[] mac, short macOffset) {
		if (mac == null || (short)(mac.length - macOffset) < HMAC_SIG_SIZE){
			ISOException.throwIt(SW_INTERNAL_BUFFER_IS_NULL_OR_TOO_SMALL);
		}
		Util.arrayCopy(mac, macOffset, 
			keyMacs, (short) (ind * HMAC_SIG_SIZE), HMAC_SIG_SIZE); 	
	}	
}


