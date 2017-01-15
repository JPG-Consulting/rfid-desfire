#include <Desfire.h>

MFRC522::StatusCode DESFire::PICC_RequestATS(byte *atsBuffer, byte *atsLength)
{
	MFRC522::StatusCode result;

	// Build command buffer
	atsBuffer[0] = 0xE0; //PICC_CMD_RATS;
	atsBuffer[1] = 0x50; // FSD=64, CID=0

	// Calculate CRC_A
	result = PCD_CalculateCRC(atsBuffer, 2, &atsBuffer[2]);
	if (result != STATUS_OK) {
		return result;
	}

	// Transmit the buffer and receive the response, validate CRC_A.
	result = PCD_TransceiveData(atsBuffer, 4, atsBuffer, atsLength, NULL, 0, true);
	if (result != STATUS_OK) {
		PICC_HaltA();
		Serial.println("WTF???");
		return result;
	}

	return result;
} // End PICC_RequestATS()

  /**
  * Transmits Protocol and Parameter Selection Request (PPS)
  *
  * @return STATUS_OK on success, STATUS_??? otherwise.
  */
MFRC522::StatusCode DESFire::PICC_ProtocolAndParameterSelection(byte cid,	///< The lower nibble indicates the CID of the selected PICC in the range of 0x00 and 0x0E
                                                                byte pps0,	///< PPS0
	                                                            byte pps1	///< PPS1
) {
	MFRC522::StatusCode result;

	byte ppsBuffer[5];
	byte ppsBufferSize = 5;
	ppsBuffer[0] = 0xD0 | (cid & 0x0F);
	ppsBuffer[1] = pps0;
	ppsBuffer[2] = pps1;

	// Calculate CRC_A
	result = PCD_CalculateCRC(ppsBuffer, 3, &ppsBuffer[3]);
	if (result != STATUS_OK) {
		return result;
	}

	// Transmit the buffer and receive the response, validate CRC_A.
	result = PCD_TransceiveData(ppsBuffer, 5, ppsBuffer, &ppsBufferSize, NULL, 0, true);
	if (result == STATUS_OK) {
		// This is how my MFRC522 is by default.
		// Reading https://www.nxp.com/documents/data_sheet/MFRC522.pdf it seems CRC generation can only be disabled in this mode.
		if (pps1 == 0x00) {
			PCD_WriteRegister(TxModeReg, 0x00);
			PCD_WriteRegister(RxModeReg, 0x00);
		}
	}

	return result;
} // End PICC_ProtocolAndParameterSelection()

/**
 * @see MIFARE_BlockExchangeWithData()
 */
DESFire::StatusCode DESFire::MIFARE_BlockExchange(mifare_desfire_tag *tag, byte cmd, byte *backData, byte *backLen)
{
	return MIFARE_BlockExchangeWithData(tag, cmd, NULL, NULL, backData, backLen);
} // End MIFARE_BlockExchange()

/**
 *
 * Frame Format for DESFire APDUs
 * ==============================
 *
 * The frame format for DESFire APDUs is based on only the ISO 14443-4 specifications for block formats.
 * This is the format used by the example firmware, and seen in Figure 3.
 *  - PCB – Protocol Control Byte, this byte is used to transfer format information about each PDU block.
 *  - CID – Card Identifier field, this byte is used to identify specific tags. It contains a 4 bit CID value as well
 *          as information on the signal strength between the reader and the tag.
 *  - NAD – Node Address field, the example firmware does not support the use of NAD.
 *  - DESFire Command Code – This is discussed in the next section.
 *  - Data Bytes – This field contains all of the Data Bytes for the command
 *
 *  |-----|-----|-----|---------|------|----------|
 *  | PCB | CID | NAD | Command | Data | Checksum |
 *  |-----|-----|-----|---------|------|----------|
 *
 * Documentation: http://read.pudn.com/downloads64/ebook/225463/M305_DESFireISO14443.pdf
 *                http://www.ti.com.cn/cn/lit/an/sloa213/sloa213.pdf
 */
DESFire::StatusCode DESFire::MIFARE_BlockExchangeWithData(mifare_desfire_tag *tag, byte cmd, byte *sendData, byte *sendLen, byte *backData, byte *backLen)
{
	StatusCode result;

	byte buffer[64];
	byte bufferSize = 64;
	byte sendSize = 3;

	buffer[0] = tag->pcb;
	buffer[1] = tag->cid;
	buffer[2] = cmd;

	// Append data if available
	if (sendData != NULL && sendLen != NULL) {
		if (*sendLen > 0) {
			memcpy(&buffer[3], sendData, *sendLen);
			sendSize = sendSize + *sendLen;
		}
	}

	// Update the PCB
	if (tag->pcb == 0x0A)
		tag->pcb = 0x0B;
	else
		tag->pcb = 0x0A;

	// Calculate CRC_A
	result.mfrc522 = PCD_CalculateCRC(buffer, sendSize, &buffer[sendSize]);
	if (result.mfrc522 != STATUS_OK) {
		return result;
	}

	result.mfrc522 = PCD_TransceiveData(buffer, sendSize + 2, buffer, &bufferSize);
	if (result.mfrc522 != STATUS_OK) {
		return result;
	}

	// Set the DESFire status code
	result.desfire = (DesfireStatusCode)(buffer[2]);

	// Copy data to backData and backLen
	if (backData != NULL && backLen != NULL) {
		memcpy(backData, &buffer[3], bufferSize - 5);
		*backLen = bufferSize - 5;
	}

	return result;
} // End MIFARE_BlockExchangeWithData()

DESFire::StatusCode DESFire::MIFARE_DESFIRE_GetVersion(mifare_desfire_tag *tag, MIFARE_DESFIRE_Version_t *versionInfo)
{
	StatusCode result;
	byte versionBuffer[64];
	byte versionBufferSize = 64;

	result = MIFARE_BlockExchange(tag, 0x60, versionBuffer, &versionBufferSize);
	if (result.mfrc522 == STATUS_OK) {
		byte hardwareVersion[2];
		byte storageSize;

		versionInfo->hardware.vendor_id = versionBuffer[0];
		versionInfo->hardware.type = versionBuffer[1];
		versionInfo->hardware.subtype = versionBuffer[2];
		versionInfo->hardware.version_major = versionBuffer[3];
		versionInfo->hardware.version_minor = versionBuffer[4];
		versionInfo->hardware.storage_size = versionBuffer[5];
		versionInfo->hardware.protocol = versionBuffer[6];

		if (result.desfire == MF_ADDITIONAL_FRAME) {
			result = MIFARE_BlockExchange(tag, 0xAF, versionBuffer, &versionBufferSize);
			if (result.mfrc522 == STATUS_OK) {
				versionInfo->software.vendor_id = versionBuffer[0];
				versionInfo->software.type = versionBuffer[1];
				versionInfo->software.subtype = versionBuffer[2];
				versionInfo->software.version_major = versionBuffer[3];
				versionInfo->software.version_minor = versionBuffer[4];
				versionInfo->software.storage_size = versionBuffer[5];
				versionInfo->software.protocol = versionBuffer[6];
			} else {
				Serial.print("Failed to send AF: ");
				Serial.println(GetStatusCodeName(result));
			}

			if (result.desfire == MF_ADDITIONAL_FRAME) {
				byte nad = 0x60;
				result = MIFARE_BlockExchange(tag, 0xAF, versionBuffer, &versionBufferSize);
				if (result.mfrc522 == STATUS_OK) {
					memcpy(versionInfo->uid, &versionBuffer[0], 7);
					memcpy(versionInfo->batch_number, &versionBuffer[7], 5);
					versionInfo->production_week = versionBuffer[12];
					versionInfo->production_year = versionBuffer[13];
				} else {
					Serial.print("Failed to send AF: ");
					Serial.println(GetStatusCodeName(result));
				}
			}

			if (result.desfire == MF_ADDITIONAL_FRAME) {
				Serial.println("GetVersion(): More data???");
			}
		}
	}
	else {
		Serial.println("Version(): Failure.");
	}

	return result;
} // End MIFARE_DESFIRE_GetVersion

DESFire::StatusCode DESFire::MIFARE_DESFIRE_SelectApplication(mifare_desfire_tag *tag, mifare_desfire_aid_t *aid)
{
	StatusCode result;

	byte buffer[64];
	byte bufferSize = MIFARE_AID_SIZE;
	
	for (byte i = 0; i < MIFARE_AID_SIZE; i++) {
		buffer[i] = aid->data[i];
	}
	
	result = MIFARE_BlockExchangeWithData(tag, 0x5A, buffer, &bufferSize, buffer, &bufferSize);
	if (IsStatusCodeOK(result)) {
		// keep track of the application
		memcpy(tag->selected_application, aid->data, MIFARE_AID_SIZE);
	}

	return result;
}

DESFire::StatusCode DESFire::MIFARE_DESFIRE_GetFileIDs(mifare_desfire_tag *tag, byte *files, byte *filesCount)
{
	StatusCode result;
	
	byte bufferSize = MIFARE_MAX_FILE_COUNT + 5;
	byte buffer[bufferSize];

	result = MIFARE_BlockExchange(tag, 0x6F, buffer, &bufferSize);
	if (IsStatusCodeOK(result)) {
		*filesCount = bufferSize;
		memcpy(files, &buffer, *filesCount);
	}

	return result;
} // End MIFARE_DESFIRE_GetFileIDs

DESFire::StatusCode DESFire::MIFARE_DESFIRE_GetFileSettings(mifare_desfire_tag *tag, byte *file, mifare_desfire_file_settings_t *fileSettings)
{
	StatusCode result;

	byte buffer[21];
	byte bufferSize = 21;
	byte sendLen = 1;

	buffer[0] = *file;

	result = MIFARE_BlockExchangeWithData(tag, 0xF5, buffer, &sendLen, buffer, &bufferSize);
	if (IsStatusCodeOK(result)) {
		fileSettings->file_type = buffer[0];
		fileSettings->communication_settings = buffer[1];
		fileSettings->access_rights = ((uint16_t)(buffer[2]) << 8) | (buffer[3]);

		switch (buffer[0]) {
			case MDFT_STANDARD_DATA_FILE:
			case MDFT_BACKUP_DATA_FILE:
				fileSettings->settings.standard_file.file_size = ((uint32_t)(buffer[4])) | ((uint32_t)(buffer[5]) << 8) | ((uint32_t)(buffer[6])  << 16);
				break;

			case MDFT_VALUE_FILE_WITH_BACKUP:
				fileSettings->settings.value_file.lower_limit = ((uint32_t)(buffer[4])) | ((uint32_t)(buffer[5]) << 8) | ((uint32_t)(buffer[6]) << 16) | ((uint32_t)(buffer[7]) << 24);
				fileSettings->settings.value_file.upper_limit = ((uint32_t)(buffer[8])) | ((uint32_t)(buffer[9]) << 8) | ((uint32_t)(buffer[10]) << 16) | ((uint32_t)(buffer[11]) << 24);
				fileSettings->settings.value_file.limited_credit_value = ((uint32_t)(buffer[12])) | ((uint32_t)(buffer[13]) << 8) | ((uint32_t)(buffer[14]) << 16) | ((uint32_t)(buffer[15]) << 24);
				fileSettings->settings.value_file.limited_credit_enabled = buffer[16];
				break;

			case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
			case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
				fileSettings->settings.record_file.record_size = ((uint32_t)(buffer[4])) | ((uint32_t)(buffer[5]) << 8) | ((uint32_t)(buffer[6]) << 16);
				fileSettings->settings.record_file.max_number_of_records = ((uint32_t)(buffer[7])) | ((uint32_t)(buffer[8]) << 8) | ((uint32_t)(buffer[9]) << 16);
				fileSettings->settings.record_file.current_number_of_records = ((uint32_t)(buffer[10])) | ((uint32_t)(buffer[11]) << 8) | ((uint32_t)(buffer[12]) << 16);
				break;

			default:
				//return FAIL;
				result.mfrc522 = STATUS_ERROR;
				return result;
		}
	}

	return result;
} // End MIFARE_DESFIRE_GetFileSettings

DESFire::StatusCode DESFire::MIFARE_DESFIRE_GetKeySettings(mifare_desfire_tag *tag, byte *settings, byte *maxKeys)
{
	StatusCode result;

	byte buffer[7];
	byte bufferSize = 7;

	result = MIFARE_BlockExchange(tag, 0x45, buffer, &bufferSize);
	if (IsStatusCodeOK(result)) {
		*settings = buffer[0];
		*maxKeys = buffer[1];
	}

	return result;
} // End MIFARE_DESFIRE_GetKeySettings()

DESFire::StatusCode DESFire::MIFARE_DESFIRE_GetKeyVersion(mifare_desfire_tag *tag, byte key, byte *version)
{
	StatusCode result;

	byte buffer[6];
	byte bufferSize = 6;
	byte sendLen = 1;

	buffer[0] = key;

	result = MIFARE_BlockExchangeWithData(tag, 0x64, buffer, &sendLen, buffer, &bufferSize);
	if (IsStatusCodeOK(result)) {
		*version = buffer[0];
	}

	return result;
}

DESFire::StatusCode DESFire::MIFARE_DESFIRE_ReadData(mifare_desfire_tag *tag, byte fid, uint32_t offset, uint32_t length, byte *backData, size_t *backLen)
{
	StatusCode result;

	byte buffer[64];
	byte bufferSize = 64;
	byte sendLen = 7;
	size_t outSize = 0;

	// file ID
	buffer[0] = fid;
	// offset
	buffer[1] = (offset & 0x00000F);
	buffer[2] = (offset & 0x00FF00) >> 8;
	buffer[3] = (offset & 0xFF0000) >> 16;
	// length
	buffer[4] = (length & 0x0000FF);
	buffer[5] = (length & 0x00FF00) >> 8;
	buffer[6] = (length & 0xFF0000) >> 16;
	
	result = MIFARE_BlockExchangeWithData(tag, 0xBD, buffer, &sendLen, buffer, &bufferSize);
	if (result.mfrc522 == STATUS_OK) {
		do {
			// Copy the data
			memcpy(backData + outSize, buffer, bufferSize);
			outSize += bufferSize;
			*backLen = outSize;

			if (result.desfire == MF_ADDITIONAL_FRAME) {
				result = MIFARE_BlockExchange(tag, 0xAF, buffer, &bufferSize);
			}
		}  while (result.mfrc522 == STATUS_OK && result.desfire == MF_ADDITIONAL_FRAME);
	}

	return result;
}

DESFire::StatusCode DESFire::MIFARE_DESFIRE_GetValue(mifare_desfire_tag *tag, byte fid, int32_t *value)
{
	StatusCode result;

	byte buffer[MFRC522::FIFO_SIZE];
	byte bufferSize = MFRC522::FIFO_SIZE;
	byte sendLen = 1;
	size_t outSize = 0;

	buffer[0] = fid;

	result = MIFARE_BlockExchangeWithData(tag, 0x6C, buffer, &sendLen, buffer, &bufferSize);
	if (IsStatusCodeOK(result)) {
		*value = ((uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) | ((uint32_t)buffer[2] << 16) | ((uint32_t)buffer[3] << 24));
	}

	return result;
} // End MIFARE_DESFIRE_GetValue()

DESFire::StatusCode DESFire::MIFARE_DESFIRE_GetApplicationIds(mifare_desfire_tag *tag, mifare_desfire_aid_t *aids, byte *applicationCount)
{
	StatusCode result;
	
	// MIFARE_MAX_APPLICATION_COUNT * MIFARE_AID_SIZE + PCB (1 byte) + CID (1 byte) + Checksum (2 bytes)
	// I also add an extra byte in case NAD is needed
	byte bufferSize = (MIFARE_MAX_APPLICATION_COUNT * MIFARE_AID_SIZE) + 5;
	byte buffer[bufferSize]; 
	byte aidBuffer[MIFARE_MAX_APPLICATION_COUNT * MIFARE_AID_SIZE];
	byte aidBufferSize = 0;

	result = MIFARE_BlockExchange(tag, 0x6A, buffer, &bufferSize);
	if (result.mfrc522 != STATUS_OK)
		return result;
		
	// MIFARE_MAX_APPLICATION_COUNT (28) * MIFARE_AID_SIZE + PCB (1) + CID (1) + Checksum (2) = 88
	// Even if the NAD byte is not present we could GET a 0xAF response.
	if (result.desfire == MF_OPERATION_OK && bufferSize == 0x00) {
		// Empty application list
		*applicationCount = 0;
		return result;
	}

	memcpy(aidBuffer, buffer, bufferSize);
	aidBufferSize = bufferSize;

	while (result.desfire == MF_ADDITIONAL_FRAME) {
		bufferSize = (MIFARE_MAX_APPLICATION_COUNT * MIFARE_AID_SIZE) + 5;
		result = MIFARE_BlockExchange(tag, 0xAF, buffer, &bufferSize);
		if (result.mfrc522 != STATUS_OK)
			return result;

		// Make sure we have space (Just in case)
		if ((aidBufferSize + bufferSize) > (MIFARE_MAX_APPLICATION_COUNT * MIFARE_AID_SIZE)) {
			result.mfrc522 = STATUS_NO_ROOM;
			return result;
		}

		// Append the new data
		memcpy(aidBuffer + aidBufferSize, buffer, bufferSize);
	}
	

	// Applications are identified with a 3 byte application identifier(AID)
	// we also received the status byte:
	if ((aidBufferSize % 3) != 0) {
		Serial.println(F("MIFARE_DESFIRE_GetApplicationIds(): Data is not a modulus of 3."));
		// TODO: Some kind of failure
		result.mfrc522 = STATUS_ERROR;
		return result;
	}

	*applicationCount = aidBufferSize / 3;
		
	for (byte i = 0; i < *applicationCount; i++) {
		aids[i].data[0] = aidBuffer[(i * 3)];
		aids[i].data[1] = aidBuffer[1 + (i * 3)];
		aids[i].data[2] = aidBuffer[2 + (i * 3)];
	}

	return result;
} // End MIFARE_DESFIRE_GetApplicationIds()

/**
 * Returns a __FlashStringHelper pointer to a status code name.
 *
 * @return const __FlashStringHelper *
 */
const __FlashStringHelper *DESFire::GetStatusCodeName(StatusCode code)
{
	if (code.mfrc522 != MFRC522::STATUS_OK) {
		return MFRC522::GetStatusCodeName(code.mfrc522);
	}

	switch (code.desfire) {
		case MF_OPERATION_OK:			return F("Successful operation.");
		case MF_NO_CHANGES:				return F("No changes done to backup files.");
		case MF_OUT_OF_EEPROM_ERROR:	return F("Insufficient NV-Mem. to complete cmd.");
		case MF_ILLEGAL_COMMAND_CODE:	return F("Command code not supported.");
		case MF_INTEGRITY_ERROR:		return F("CRC or MAC does not match data.");
		case MF_NO_SUCH_KEY:			return F("Invalid key number specified.");
		case MF_LENGTH_ERROR:			return F("Length of command string invalid.");
		case MF_PERMISSION_ERROR:		return F("Curr conf/status doesnt allow cmd.");
		case MF_PARAMETER_ERROR:		return F("Value of the parameter(s) invalid.");
		case MF_APPLICATION_NOT_FOUND:	return F("Requested AID not present on PICC.");
		case MF_APPL_INTEGRITY_ERROR:	return F("Unrecoverable err within app.");
		case MF_AUTHENTICATION_ERROR:	return F("Current authentication status doesn't allow requested command.");
		case MF_ADDITIONAL_FRAME:		return F("Additional data frame to be sent.");
		case MF_BOUNDARY_ERROR:			return F("Attempt to read/write beyond limits.");
		case MF_PICC_INTEGRITY_ERROR:	return F("Unrecoverable error within PICC.");
		case MF_COMMAND_ABORTED:		return F("Previous command not fully completed.");
		case MF_PICC_DISABLED_ERROR:	return F("PICC disabled by unrecoverable error.");
		case MF_COUNT_ERROR:			return F("Cant create more apps, already @ 28.");
		case MF_DUPLICATE_ERROR:		return F("Cant create dup. file/app.");
		case MF_EEPROM_ERROR:			return F("Couldnt complete NV-write operation.");
		case MF_FILE_NOT_FOUND:			return F("Specified file number doesnt exist.");
		case MF_FILE_INTEGRITY_ERROR:	return F("Unrecoverable error within file.");
		default:						return F("Unknown error");
	}
} // End GetStatusCodeName()

const __FlashStringHelper *DESFire::GetFileTypeName(mifare_desfire_file_types fileType)
{
	switch (fileType) {
		case MDFT_STANDARD_DATA_FILE:				return F("Standard data file.");
		case MDFT_BACKUP_DATA_FILE:					return F("Backup data file.");
		case MDFT_VALUE_FILE_WITH_BACKUP:			return F("Value file with backup.");
		case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:	return F("Linear record file with backup.");
		case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:	return F("Cyclic record file with backup.");
		default:									return F("Unknown file type.");
	}
} // End GetFileTypeName()

const __FlashStringHelper *DESFire::GetCommunicationModeName(mifare_desfire_communication_modes communicationMode)
{
	switch (communicationMode) {
		case MDCM_PLAIN:		return(F("Plain Communication."));
		case MDCM_MACED:        return(F("Plain Comm secured by DES/3DES MACing."));
		case MDCM_ENCIPHERED:   return(F("Fully DES/3DES enciphered comm."));
		default:				return F("Unknown communication mode.");
	}
} // End GetCommunicationModeName()

bool DESFire::IsStatusCodeOK(StatusCode code)
{
	if (code.mfrc522 != STATUS_OK)
		return false;
	if (code.desfire != MF_OPERATION_OK)
		return false;

	return true;
} // End IsStatusCodeOK();

void DESFire::PICC_DumpMifareDesfireMasterKey(mifare_desfire_tag *tag)
{
	StatusCode response;
	mifare_desfire_aid_t aid;

	aid.data[0] = 0x00;
	aid.data[1] = 0x00;
	aid.data[2] = 0x00;

	Serial.println(F("-- Desfire Master Key ---------------------------------------"));
	Serial.println(F("-------------------------------------------------------------"));
	// Select the current application.
	response = MIFARE_DESFIRE_SelectApplication(tag, &aid);
	if (!IsStatusCodeOK(response)) {
		Serial.println(F("Error: Failed to select application."));
		Serial.println(GetStatusCodeName(response));
		Serial.println(F("-------------------------------------------------------------"));
		return;
	}

	// Get Key settings
	byte keySettings;
	byte keyCount = 0;
	byte keyVersion;

	response = MIFARE_DESFIRE_GetKeySettings(tag, &keySettings, &keyCount);
	if (IsStatusCodeOK(response)) {
		Serial.print(F("  Key settings       : 0x"));
		if (keySettings < 0x10)
			Serial.print(F("0"));
		Serial.println(keySettings, HEX);

		Serial.print(F("  Max num keys       : "));
		Serial.println(keyCount);

		// Output key versions
		if (keyCount > 0) {
			Serial.println(F("  ----------------------------------------------------------"));
			Serial.println(F("  Key Versions"));

			// Get key versions (No output will be outputed later)
			for (byte ixKey = 0; ixKey < keyCount; ixKey++) {
				response = MIFARE_DESFIRE_GetKeyVersion(tag, ixKey, &keyVersion);
				Serial.print(F("      Key 0x"));
				if (ixKey < 0x10)
					Serial.print(F("0"));
				Serial.print(ixKey, HEX);
				Serial.print(F("       : "));
				
				if (IsStatusCodeOK(response)) {
					Serial.print(F("0x"));
					if (keyVersion < 0x10)
						Serial.print(F("0"));
					Serial.println(keyVersion, HEX);
				} else {
					Serial.println(GetStatusCodeName(response));
				}
			}
		}
	}
	else {
		Serial.println(F("  Error: Failed to get application key settings."));
		// Just to be sure..
		keyCount = 0;
	}

	Serial.println(F("-------------------------------------------------------------"));
} // End PICC_DumpMifareDesfireMasterKey()

void DESFire::PICC_DumpMifareDesfireVersion(mifare_desfire_tag *tag, MIFARE_DESFIRE_Version_t *versionInfo)
{
	Serial.println(F("-- Desfire Information --------------------------------------"));
	Serial.println(F("-------------------------------------------------------------"));
	switch (versionInfo->hardware.version_major) {
	case 0x00:
		Serial.println(F("  Card type          : MIFARE DESFire (MF3ICD40)"));
		switch (versionInfo->hardware.storage_size) {
		case 0x16:
			Serial.print(F(" 2K"));
			break;
		case 0x18:
			Serial.print(F(" 4K"));
			break;
		case 0x1A:
			Serial.print(F(" 8K"));
			break;
		}
		Serial.println();
		break;
	case 0x01:
		Serial.print(F("  Card type          : MIFARE DESFire EV1"));
		switch (versionInfo->hardware.storage_size) {
		case 0x16:
			Serial.print(F(" 2K"));
			break;
		case 0x18:
			Serial.print(F(" 4K"));
			break;
		case 0x1A:
			Serial.print(F(" 8K"));
			break;
		}
		Serial.println();
		break;
	case 0x12:
		Serial.print(F("  Card type          : MIFARE DESFire EV2"));
		switch (versionInfo->hardware.storage_size) {
		case 0x16:
			Serial.print(F(" 2K"));
			break;
		case 0x18:
			Serial.print(F(" 4K"));
			break;
		case 0x1A:
			Serial.print(F(" 8K"));
			break;
		}
		Serial.println();
		break;
	}

	// UID
	Serial.print(F("  UID                :"));
	for (byte i = 0; i < 7; i++) {
		if (versionInfo->uid[i] < 0x10)
			Serial.print(F(" 0"));
		else
			Serial.print(F(" "));
		Serial.print(versionInfo->uid[i], HEX);
	}
	Serial.println();

	// Batch
	Serial.print(F("  Batch number       :"));
	for (byte i = 0; i < 5; i++) {
		if (versionInfo->batch_number[i] < 0x10)
			Serial.print(F(" 0"));
		else
			Serial.print(F(" "));
		Serial.print(versionInfo->batch_number[i], HEX);
	}
	Serial.println();

	Serial.print(F("  Production week    : 0x"));
	if (versionInfo->production_week < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->production_week, HEX);

	Serial.print(F("  Production year    : 0x"));
	if (versionInfo->production_year < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->production_year, HEX);

	Serial.println(F("  ----------------------------------------------------------"));
	Serial.println(F("  Hardware Information"));
	Serial.print(F("      Vendor ID      : 0x"));
	if (versionInfo->hardware.vendor_id < 0x10)
		Serial.print(F("0"));
	Serial.print(versionInfo->hardware.vendor_id, HEX);
	if (versionInfo->hardware.vendor_id == 0x04)
		Serial.print(F(" (NXP)"));
	Serial.println();

	Serial.print(F("      Type           : 0x"));
	if (versionInfo->hardware.type < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->hardware.type, HEX);

	Serial.print(F("      Subtype        : 0x"));
	if (versionInfo->hardware.subtype < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->hardware.subtype, HEX);

	Serial.print(F("      Version        : "));
	Serial.print(versionInfo->hardware.version_major);
	Serial.print(F("."));
	Serial.println(versionInfo->hardware.version_minor);

	Serial.print(F("      Storage size   : 0x"));
	if (versionInfo->hardware.storage_size < 0x10)
		Serial.print(F("0"));
	Serial.print(versionInfo->hardware.storage_size, HEX);
	switch (versionInfo->hardware.storage_size) {
	case 0x16:
		Serial.print(F(" (2048 bytes)"));
		break;
	case 0x18:
		Serial.print(F(" (4096 bytes)"));
		break;
	case 0x1A:
		Serial.print(F(" (8192 bytes)"));
		break;
	}
	Serial.println();

	Serial.print(F("      Protocol       : 0x"));
	if (versionInfo->hardware.protocol < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->hardware.protocol, HEX);

	Serial.println(F("  ----------------------------------------------------------"));
	Serial.println(F("  Software Information"));
	Serial.print(F("      Vendor ID      : 0x"));
	if (versionInfo->software.vendor_id < 0x10)
		Serial.print(F("0"));
	Serial.print(versionInfo->software.vendor_id, HEX);
	if (versionInfo->software.vendor_id == 0x04)
		Serial.print(F(" (NXP)"));
	Serial.println();

	Serial.print(F("      Type           : 0x"));
	if (versionInfo->software.type < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->software.type, HEX);

	Serial.print(F("      Subtype        : 0x"));
	if (versionInfo->software.subtype < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->software.subtype, HEX);

	Serial.print(F("      Version        : "));
	Serial.print(versionInfo->software.version_major);
	Serial.print(F("."));
	Serial.println(versionInfo->software.version_minor);

	Serial.print(F("      Storage size   : 0x"));
	if (versionInfo->software.storage_size < 0x10)
		Serial.print(F("0"));
	Serial.print(versionInfo->software.storage_size, HEX);
	switch (versionInfo->software.storage_size) {
	case 0x16:
		Serial.print(F(" (2048 bytes)"));
		break;
	case 0x18:
		Serial.print(F(" (4096 bytes)"));
		break;
	case 0x1A:
		Serial.print(F(" (8192 bytes)"));
		break;
	}
	Serial.println();

	Serial.print(F("      Protocol       : 0x"));
	if (versionInfo->software.protocol < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->software.protocol, HEX);

	Serial.println(F("-------------------------------------------------------------"));
}

void DESFire::PICC_DumpMifareDesfireApplication(mifare_desfire_tag *tag, mifare_desfire_aid_t *aid)
{
	StatusCode response;

	Serial.println(F("-- Desfire Application --------------------------------------"));
	Serial.println(F("-------------------------------------------------------------"));
	Serial.print(F("  AID                :"));
	for (byte i = 0; i < 3; i++) {
		if (aid->data[i] < 0x10)
			Serial.print(F(" 0"));
		else
			Serial.print(F(" "));
		Serial.print(aid->data[i], HEX);
	}
	Serial.println();

	// Select the current application.
	response = MIFARE_DESFIRE_SelectApplication(tag, aid);
	if (!IsStatusCodeOK(response)) {
		Serial.println(F("Error: Failed to select application."));
		Serial.println(GetStatusCodeName(response));
		Serial.println(F("-------------------------------------------------------------"));
		return;
	}

	// Get Key settings
	byte keySettings;
	byte keyCount = 0;
	byte keyVersion[16];

	response = MIFARE_DESFIRE_GetKeySettings(tag, &keySettings, &keyCount);
	if (IsStatusCodeOK(response)) {
		Serial.print(F("  Key settings       : 0x"));
		if (keySettings < 0x10)
			Serial.print(F("0"));
		Serial.println(keySettings, HEX);

		Serial.print(F("  Max num keys       : "));
		Serial.println(keyCount);

		// Get key versions (No output will be outputed later)
		for (byte ixKey = 0; ixKey < keyCount; ixKey++) {
			response = MIFARE_DESFIRE_GetKeyVersion(tag, ixKey, &(keyVersion[ixKey]));
			if (!IsStatusCodeOK(response))
				keyVersion[ixKey] = 0x00;
		}
		
	} else {
		Serial.println(F("  Error: Failed to get application key settings."));
		// Just to be sure..
		keyCount = 0;
	}

	// Get the files
	byte files[MIFARE_MAX_FILE_COUNT];
	byte filesCount = 0;
	response = MIFARE_DESFIRE_GetFileIDs(tag, files, &filesCount);
	if (!IsStatusCodeOK(response)) {
		Serial.println(F("  Error: Failed to get application file IDs."));
		Serial.print(F("  "));
		Serial.println(GetStatusCodeName(response));
		Serial.println(F("-------------------------------------------------------------"));
		return;
	}

	// Number of files
	Serial.print(F("  Num. Files         : "));
	Serial.println(filesCount);

	// Output key versions
	if (keyCount > 0) {
		Serial.println(F("  ----------------------------------------------------------"));
		Serial.println(F("  Key Versions"));
		for (byte ixKey = 0; ixKey < keyCount; ixKey++) {
			Serial.print(F("      Key 0x"));
			if (ixKey < 0x10)
				Serial.print(F("0"));
			Serial.print(ixKey, HEX);
			Serial.print(F("       : 0x"));
			if (keyVersion[ixKey] < 0x10)
				Serial.print(F("0"));
			Serial.println(keyVersion[ixKey], HEX);
		}
	}
	
	for (byte i = 0; i < filesCount; i++) {
		Serial.println(F("  ----------------------------------------------------------"));
		Serial.println(F("  File Information"));
		Serial.print(F("      File ID        : 0x"));
		if (files[i] < 0x10)
			Serial.print(F("0"));
		Serial.println(files[i], HEX);

		// Get file settings
		mifare_desfire_file_settings_t fileSettings;

		response = MIFARE_DESFIRE_GetFileSettings(tag, &(files[i]), &fileSettings);
		if (IsStatusCodeOK(response)) {
			Serial.print(F("      File Type      : 0x"));
			if (fileSettings.file_type < 0x10)
				Serial.print(F("0"));
			Serial.print(fileSettings.file_type, HEX);
			Serial.print(F(" ("));
			Serial.print(GetFileTypeName((mifare_desfire_file_types)fileSettings.file_type));
			Serial.println(F(")"));

			Serial.print(F("      Communication  : 0x"));
			if (fileSettings.communication_settings < 0x10)
				Serial.print(F("0"));
			Serial.print(fileSettings.communication_settings, HEX);
			Serial.print(F(" ("));
			Serial.print(GetCommunicationModeName((mifare_desfire_communication_modes)fileSettings.communication_settings));
			Serial.println(F(")"));

			Serial.print(F("      Access rights  : 0x"));
			Serial.println(fileSettings.access_rights, HEX);

			switch (fileSettings.file_type) {
				case MDFT_STANDARD_DATA_FILE:
				case MDFT_BACKUP_DATA_FILE:
					Serial.print(F("      File Size      : "));
					Serial.print(fileSettings.settings.standard_file.file_size);
					Serial.println(F(" bytes"));
					break;
				case MDFT_VALUE_FILE_WITH_BACKUP:
					Serial.print(F("      Lower Limit    : "));
					Serial.println(fileSettings.settings.value_file.lower_limit);
					Serial.print(F("      Upper Limit    : "));
					Serial.println(fileSettings.settings.value_file.upper_limit);
					Serial.print(F("      Limited credit : "));
					Serial.println(fileSettings.settings.value_file.limited_credit_value);
					Serial.print(F("      Limited credit : "));
					
					if (fileSettings.settings.value_file.limited_credit_enabled == 0x00)
						Serial.print(F("Disabled ("));
					else
						Serial.print(F("Enabled (0x"));
					if (fileSettings.settings.value_file.limited_credit_enabled < 0x10)
						Serial.print(F("0"));
					Serial.print(fileSettings.settings.value_file.limited_credit_enabled, HEX);
					Serial.println(F(")"));
	
					break;

				case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
				case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
					Serial.print(F("      Record size    : "));
					Serial.println(fileSettings.settings.record_file.record_size);
					Serial.print(F("      max num records: "));
					Serial.println(fileSettings.settings.record_file.max_number_of_records);
					Serial.print(F("      num records    : "));
					Serial.println(fileSettings.settings.record_file.current_number_of_records);
					break;
			}

			switch (fileSettings.file_type) {
				case MDFT_STANDARD_DATA_FILE:
				case MDFT_BACKUP_DATA_FILE:
				{
					// Get file data
					byte fileContent[fileSettings.settings.standard_file.file_size];
					size_t fileContentLength = fileSettings.settings.standard_file.file_size;
					response = MIFARE_DESFIRE_ReadData(tag, files[i], 0, fileSettings.settings.standard_file.file_size, fileContent, &fileContentLength);
					if (response.mfrc522 == STATUS_OK) {
						Serial.println(F("      ------------------------------------------------------"));
						Serial.println(F("      Data"));

						if (response.desfire == MF_OPERATION_OK || response.desfire == MF_ADDITIONAL_FRAME) {
							for (unsigned int iByte = 0; iByte < fileContentLength; iByte++) {
								if ((iByte % 16) == 0) {
									if (iByte != 0)
										Serial.println();
									Serial.print(F("           "));
								}
								if (fileContent[iByte] < 0x10)
									Serial.print(F(" 0"));
								else
									Serial.print(F(" "));
								Serial.print(fileContent[iByte], HEX);
							}
							Serial.println();
						}
						else {
							Serial.print(F("           "));
							Serial.println(GetStatusCodeName(response));
						}
					}
				}
				break;
				case MDFT_VALUE_FILE_WITH_BACKUP:
				{
					// Get value
					int32_t fileValue;
					response = MIFARE_DESFIRE_GetValue(tag, files[i], &fileValue);
					Serial.print(F("      Value          : "));
					if (IsStatusCodeOK(response)) {
						Serial.println(fileValue);
					} else {
						Serial.println(GetStatusCodeName(response));
					}
				}
				break;
			}

		} else {
			Serial.println(F("      Error: Failed to get file settings."));
			Serial.print(F("      "));
			Serial.println(GetStatusCodeName(response));
		}
	}


	Serial.println(F("-------------------------------------------------------------"));
}