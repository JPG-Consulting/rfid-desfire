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
	StatusCode result;

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
 * Documentation: http://read.pudn.com/downloads64/ebook/225463/M305_DESFireISO14443.pdf
 */
MFRC522::StatusCode DESFire::MIFARE_BlockExchange(byte pcb, byte cid, byte cmd, byte *backData, byte *backLen)
{
	StatusCode result;

	byte buffer[64];
	byte bufferSize = 64;

	buffer[0] = pcb;
	buffer[1] = cid;
	buffer[2] = cmd;

	// Calculate CRC_A
	result = PCD_CalculateCRC(buffer, 3, &buffer[3]);
	if (result != STATUS_OK) {
		return result;
	}

	result = PCD_TransceiveData(buffer, 5, buffer, &bufferSize);
	if (result != STATUS_OK) {
		return result;
	}

	// TODO: Sanity checks.
	memcpy(backData, &buffer[2], bufferSize - 4);
	*backLen = bufferSize - 4;

	return STATUS_OK;
} // End MIFARE_BlockExchange()

MFRC522::StatusCode DESFire::MIFARE_BlockExchangeWithData(byte pcb, byte cid, byte cmd, byte *sendData, byte *sendLen, byte *backData, byte *backLen)
{
	StatusCode result;

	byte buffer[64];
	byte bufferSize = 64;
	byte sendSize = 3;

	buffer[0] = pcb;
	buffer[1] = cid;
	buffer[2] = cmd;

	// Append data if available
	if (sendData != NULL && sendLen != NULL) {
		if (*sendLen > 0) {
			memcpy(&buffer[3], sendData, *sendLen);
			sendSize = sendSize + *sendLen;
		}

	}

	// Calculate CRC_A
	result = PCD_CalculateCRC(buffer, sendSize, &buffer[sendSize]);
	if (result != STATUS_OK) {
		return result;
	}

	result = PCD_TransceiveData(buffer, sendSize + 2, buffer, &bufferSize);
	if (result != STATUS_OK) {
		return result;
	}

	// TODO: Sanity checks.
	memcpy(backData, &buffer[2], bufferSize - 4);
	*backLen = bufferSize - 4;

	return STATUS_OK;
} // End MIFARE_BlockExchangeWithData()

MFRC522::StatusCode DESFire::MIFARE_DESFIRE_GetVersion(MIFARE_DESFIRE_Version_t *versionInfo)
{
	StatusCode result;

	byte versionBuffer[64];
	byte versionBufferSize = 64;

	// PCB
	// 0x0A = 0000 1010

	result = MIFARE_BlockExchange(0x0A, 0x00, 0x60, versionBuffer, &versionBufferSize);
	if (result == STATUS_OK) {
		byte hardwareVersion[2];
		byte storageSize;

		versionInfo->hardware.vendor_id = versionBuffer[1];
		versionInfo->hardware.type = versionBuffer[2];
		versionInfo->hardware.subtype = versionBuffer[3];
		versionInfo->hardware.version_major = versionBuffer[4];
		versionInfo->hardware.version_minor = versionBuffer[5];
		versionInfo->hardware.storage_size = versionBuffer[6];
		versionInfo->hardware.protocol = versionBuffer[7];

		if (versionBuffer[0] == 0xAF) {
			result = MIFARE_BlockExchange(0x0B, 0x00, 0xAF, versionBuffer, &versionBufferSize);
			if (result == STATUS_OK) {
				versionInfo->software.vendor_id = versionBuffer[1];
				versionInfo->software.type = versionBuffer[2];
				versionInfo->software.subtype = versionBuffer[3];
				versionInfo->software.version_major = versionBuffer[4];
				versionInfo->software.version_minor = versionBuffer[5];
				versionInfo->software.storage_size = versionBuffer[6];
				versionInfo->software.protocol = versionBuffer[7];
			}
			else {
				Serial.print("Failed to send AF: ");
				Serial.println(GetStatusCodeName(result));
			}

			if (versionBuffer[0] == 0xAF) {
				byte nad = 0x60;
				result = MIFARE_BlockExchange(0x0A, 0x00, 0xAF, versionBuffer, &versionBufferSize);
				if (result == STATUS_OK) {
					memcpy(versionInfo->uid, &versionBuffer[1], 7);
					memcpy(versionInfo->batch_number, &versionBuffer[8], 5);
					versionInfo->production_week = versionBuffer[13];
					versionInfo->production_year = versionBuffer[14];
				}
				else {
					Serial.print("Failed to send AF: ");
					Serial.println(GetStatusCodeName(result));
				}
			}

			if (versionBuffer[0] == 0xAF) {
				Serial.println("GetVersion(): More data???");
			}
		}
	}
	else {
		Serial.println("Version(): Failure.");
	}

	return result;
} // End MIFARE_DESFIRE_GetVersion

MFRC522::StatusCode DESFire::MIFARE_DESFIRE_SelectApplication(mifare_desfire_aid_t *aid)
{
	StatusCode result;

	byte buffer[64];
	byte bufferSize = 3;

	// PCB
	// 0x0A = 0000 1010
	buffer[0] = aid->data[0];
	buffer[1] = aid->data[1];
	buffer[2] = aid->data[2];

	result = MIFARE_BlockExchangeWithData(0x0A, 0x00, 0x5A, buffer, &bufferSize, buffer, &bufferSize);
	if (result != STATUS_OK) {
		return result;
	}

	if (buffer[0] == 0x00) {
		return STATUS_OK;
	}

	// TODO: Implement DESFire status codes
	return STATUS_ERROR;
}

MFRC522::StatusCode DESFire::MIFARE_DESFIRE_GetFileIDs(byte *files, byte *filesCount)
{
	StatusCode result;

	byte buffer[255];
	byte bufferSize = 255;

	// PCB
	// 0x0A = 0000 1010

	//result = MIFARE_BlockExchange(0x0A, 0x00, 0x6A, versionBuffer, &versionBufferSize);
	result = MIFARE_BlockExchange(0x0B, 0x00, 0x6F, buffer, &bufferSize);
	if (result == STATUS_OK) {
		*filesCount = bufferSize - 1;
		memcpy(files, &(buffer[1]), *filesCount);
	} else {
		Serial.println("Get file IDs: Failure.");
	}

	return result;
} // End MIFARE_DESFIRE_GetFileIDs

MFRC522::StatusCode DESFire::MIFARE_DESFIRE_GetFileSettings(byte *file, mifare_desfire_file_settings_t *fileSettings)
{
	StatusCode result;

	byte pcb = 0x0A;
	byte buffer[64];
	byte bufferSize = 64;
	byte sendLen = 1;

	// PCB
	// 0x0A = 0000 1010
	buffer[0] = *file;
	
	if (last_pcb == 0x0A) {
		pcb = 0x0B;
		last_pcb = 0x0B;
	} else {
		pcb = 0x0A;
		last_pcb = 0x0A;
	}
	//result = MIFARE_BlockExchangeWithData(0x0A, 0x00, 0xF5, buffer, &bufferSize, versionBuffer, &versionBufferSize);
	result = MIFARE_BlockExchangeWithData(pcb, 0x00, 0xF5, buffer, &sendLen, buffer, &bufferSize);
	if (result == STATUS_OK) {
		fileSettings->file_type = buffer[1];
		fileSettings->communication_settings = buffer[2];
		fileSettings->access_rights = ((uint16_t)(buffer[3]) << 8) | (buffer[4]);

		switch (buffer[1]) {
			case MDFT_STANDARD_DATA_FILE:
			case MDFT_BACKUP_DATA_FILE:
				//fileSettings->settings.standard_file.file_size = ((uint32_t)(buffer[5]) << 16) | ((uint32_t)(buffer[6]) << 8) | ((uint32_t)(buffer[7]));
				fileSettings->settings.standard_file.file_size = ((uint32_t)(buffer[5])) | ((uint32_t)(buffer[6]) << 8) | ((uint32_t)(buffer[7])  << 16);
				break;

			case MDFT_VALUE_FILE_WITH_BACKUP:
				fileSettings->settings.value_file.lower_limit = ((uint32_t)(buffer[5])) | ((uint32_t)(buffer[6]) << 8) | ((uint32_t)(buffer[7]) << 16) | ((uint32_t)(buffer[8]) << 24);
				fileSettings->settings.value_file.upper_limit = ((uint32_t)(buffer[9])) | ((uint32_t)(buffer[10]) << 8) | ((uint32_t)(buffer[11]) << 16) | ((uint32_t)(buffer[12]) << 24);
				fileSettings->settings.value_file.limited_credit_value = ((uint32_t)(buffer[13])) | ((uint32_t)(buffer[14]) << 8) | ((uint32_t)(buffer[15]) << 16) | ((uint32_t)(buffer[16]) << 24);
				fileSettings->settings.value_file.limited_credit_enabled = buffer[17];
				break;

			case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
			case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
				fileSettings->settings.record_file.record_size = ((uint32_t)(buffer[5])) | ((uint32_t)(buffer[6]) << 8) | ((uint32_t)(buffer[7]) << 16);
				fileSettings->settings.record_file.max_number_of_records = ((uint32_t)(buffer[8])) | ((uint32_t)(buffer[9]) << 8) | ((uint32_t)(buffer[10]) << 16);
				fileSettings->settings.record_file.current_number_of_records = ((uint32_t)(buffer[11])) | ((uint32_t)(buffer[12]) << 8) | ((uint32_t)(buffer[13]) << 16);
				break;

			default:
				//return FAIL;
				return STATUS_ERROR;
		}
		
		//Serial.println("Get file Settings: Success.");
		//Serial.print("Buffer size: ");
		//Serial.println(bufferSize);
		//
		//Serial.print(F("File Settings:"));
		//for (byte i = 0; i < bufferSize; i++) {
		//	if (buffer[i] < 0x10)
		//		Serial.print(F(" 0"));
		//	else
		//		Serial.print(F(" "));
		//	Serial.print(buffer[i], HEX);
		//}
		//Serial.println();
	} else {
		Serial.print("Get file Settings: ");
		Serial.println(GetStatusCodeName(result));
	}

	return result;
} // End MIFARE_DESFIRE_GetFileSettings

MFRC522::StatusCode DESFire::MIFARE_DESFIRE_GetApplicationIds(mifare_desfire_aid_t *aids, byte *applicationCount)
{
	StatusCode result;

	byte buffer[255];
	byte bufferSize = 255;

	// PCB
	// 0x0A = 0000 1010

	//result = MIFARE_BlockExchange(0x0A, 0x00, 0x6A, versionBuffer, &versionBufferSize);
	result = MIFARE_BlockExchange(0x0B, 0x00, 0x6A, buffer, &bufferSize);
	if (result == STATUS_OK) {
		if (bufferSize == 0x01) {
			if (buffer[0] == 0x00) {
				// Empty application list
				Serial.println("No applications in card!");
				return STATUS_OK;
			}
			else {
				// TODO: Implement MIFARE DESFIRE STATUS CODES
				Serial.println("MIFARE_DESFIRE_GetApplicationIds(): Failed.");
				return STATUS_ERROR;
			}
		}

		// Applications are identified with a 3 byte application identifier(AID)
		// we also received the status byte:
		if (((bufferSize - 1) % 3) != 0) {
			Serial.println("MIFARE_DESFIRE_GetApplicationIds(): Data is not a modulus of 3.");
			return STATUS_ERROR;
		}

		*applicationCount = (bufferSize - 1) / 3;
		
		for (byte i = 0; i < *applicationCount; i++) {
			aids[i].data[0] = buffer[1 + (i * 3)];
			aids[i].data[1] = buffer[2 + (i * 3)];
			aids[i].data[2] = buffer[3 + (i * 3)];
		}
	} else {
		Serial.println("Application IDs: Failure.");
	}

	return result;
} // End MIFARE_DESFIRE_GetApplicationIds()

  /**
  * Returns a __FlashStringHelper pointer to a status code name.
  *
  * @return const __FlashStringHelper *
  */
const __FlashStringHelper *DESFire::GetDesfireStatusCodeName(DESFire::DesfireStatusCode code	///< One of the DesfireStatusCode enums.
) {
	switch (code) {
		case MF_OPERATION_OK:			return F("successful operation.");
		case MF_NO_CHANGES:				return F("no changes done to backup files.");
		case MF_OUT_OF_EEPROM_ERROR:	return F("insufficient NV-Mem. to complete cmd.");
		case MF_ILLEGAL_COMMAND_CODE:	return F("command code not supported.");
		case MF_INTEGRITY_ERROR:		return F("CRC or MAC does not match data.");
		case MF_NO_SUCH_KEY:			return F("invalid key number specified.");
		case MF_LENGTH_ERROR:			return F("length of command string invalid.");
		case MF_PERMISSION_ERROR:		return F("curr conf/status doesnt allow cmd.");
		case MF_PARAMETER_ERROR:		return F("value of the parameter(s) invalid.");
		case MF_APPLICATION_NOT_FOUND:	return F("requested AID not present on PICC.");
		case MF_APPL_INTEGRITY_ERROR:	return F("unrecoverable err within app.");
		case MF_AUTHENTICATION_ERROR:	return F("cur auth status doesnt allow req cmd.");
		case MF_ADDITIONAL_FRAME:		return F("additional data frame to be sent.");
		case MF_BOUNDARY_ERROR:			return F("attempt to read/write beyond limits.");
		case MF_PICC_INTEGRITY_ERROR:	return F("unrecoverable error within PICC.");
		case MF_COMMAND_ABORTED:		return F("previous command not fully completed.");
		case MF_PICC_DISABLED_ERROR:	return F("PICC disabled by unrecoverable error.");
		case MF_COUNT_ERROR:			return F("cant create more apps, already @ 28.");
		case MF_DUPLICATE_ERROR:		return F("cant create dup. file/app.");
		case MF_EEPROM_ERROR:			return F("couldnt complete NV-write operation.");
		case MF_FILE_NOT_FOUND:			return F("specified file number doesnt exist.");
		case MF_FILE_INTEGRITY_ERROR:	return F("unrecoverable error within file.");
		default:						return F("Unknown error");
	}
} // End GetDesfireStatusCodeName()


void DESFire::PICC_DumpMifareDesfireVersion(MIFARE_DESFIRE_Version_t *versionInfo)
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

	Serial.print(F("  Production week    : "));
	Serial.println(versionInfo->production_week, HEX);

	Serial.print(F("  Production year    : "));
	Serial.println(versionInfo->production_year, HEX);

	Serial.println(F("  ----------------------------------------------------------"));
	Serial.println(F("  Hardware Information"));
	Serial.print(F("      Vendor ID      : "));
	if (versionInfo->hardware.vendor_id < 0x10)
		Serial.print(F("0"));
	Serial.print(versionInfo->hardware.vendor_id, HEX);
	if (versionInfo->hardware.vendor_id == 0x04)
		Serial.print(F(" (NXP)"));
	Serial.println();

	Serial.print(F("      Type           : "));
	if (versionInfo->hardware.type < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->hardware.type, HEX);

	Serial.print(F("      Subtype        : "));
	if (versionInfo->hardware.subtype < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->hardware.subtype, HEX);

	Serial.print(F("      Version        : "));
	Serial.print(versionInfo->hardware.version_major);
	Serial.print(F("."));
	Serial.println(versionInfo->hardware.version_minor);

	Serial.print(F("      Storage size   : "));
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

	Serial.print(F("      Protocol       : "));
	if (versionInfo->hardware.protocol < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->hardware.protocol, HEX);

	Serial.println(F("  ----------------------------------------------------------"));
	Serial.println(F("  Software Information"));
	Serial.print(F("      Vendor ID      : "));
	if (versionInfo->software.vendor_id < 0x10)
		Serial.print(F("0"));
	Serial.print(versionInfo->software.vendor_id, HEX);
	if (versionInfo->software.vendor_id == 0x04)
		Serial.print(F(" (NXP)"));
	Serial.println();

	Serial.print(F("      Type           : "));
	if (versionInfo->software.type < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->software.type, HEX);

	Serial.print(F("      Subtype        : "));
	if (versionInfo->software.subtype < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->software.subtype, HEX);

	Serial.print(F("      Version        : "));
	Serial.print(versionInfo->software.version_major);
	Serial.print(F("."));
	Serial.println(versionInfo->software.version_minor);

	Serial.print(F("      Storage size   : "));
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

	Serial.print(F("      Protocol       : "));
	if (versionInfo->software.protocol < 0x10)
		Serial.print(F("0"));
	Serial.println(versionInfo->software.protocol, HEX);

	Serial.println(F("-------------------------------------------------------------"));
}

void DESFire::PICC_DumpMifareDesfireApplication(mifare_desfire_aid_t *aid, byte *files, byte *filesCount, mifare_desfire_file_settings_t *fileSettings)
{
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

	// Number of files
	Serial.print(F("  Num. Files         : "));
	Serial.println(*filesCount);

	for (byte i = 0; i < *filesCount; i++) {
		Serial.println(F("  ----------------------------------------------------------"));
		Serial.println(F("  File Information"));
		Serial.print(F("      File ID        : "));
		if (files[i] < 0x10)
			Serial.print(F("0"));
		Serial.println(files[i], HEX);

		Serial.print(F("      File Type      : "));
		if (fileSettings[i].file_type < 0x10)
			Serial.print(F("0"));
		Serial.println(fileSettings[i].file_type, HEX);

		Serial.print(F("      Communication  : "));
		if (fileSettings[i].communication_settings < 0x10)
			Serial.print(F("0"));
		Serial.println(fileSettings[i].communication_settings, HEX);

		Serial.print(F("      Access rights  : "));
		Serial.println(fileSettings[i].access_rights, HEX);

		switch (fileSettings[i].file_type) {
			case MDFT_STANDARD_DATA_FILE:
			case MDFT_BACKUP_DATA_FILE:
				Serial.print(F("      File Size      : "));
				Serial.println(fileSettings[i].settings.standard_file.file_size);
				break;
			case MDFT_VALUE_FILE_WITH_BACKUP:
				Serial.print(F("      Lower Limit    : "));
				Serial.println(fileSettings[i].settings.value_file.lower_limit);
				Serial.print(F("      Upper Limit    : "));
				Serial.println(fileSettings[i].settings.value_file.upper_limit);
				Serial.print(F("      Limited credit : "));
				Serial.println(fileSettings[i].settings.value_file.limited_credit_value);
				Serial.print(F("      Limited credit : "));
				//
				if (fileSettings[i].settings.value_file.limited_credit_enabled == 0x00)
					Serial.print(F("Disabled ("));
				else
					Serial.print(F("Enabled ("));
				if (fileSettings[i].settings.value_file.limited_credit_enabled < 0x10)
					Serial.print(F("0"));
				Serial.print(fileSettings[i].settings.value_file.limited_credit_enabled, HEX);
				Serial.println(F(")"));
				
				break;

			case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
			case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
				Serial.print(F("      Record size    : "));
				Serial.println(fileSettings[i].settings.record_file.record_size);
				Serial.print(F("      max num records: "));
				Serial.println(fileSettings[i].settings.record_file.max_number_of_records);
				Serial.print(F("      num records    : "));
				Serial.println(fileSettings[i].settings.record_file.current_number_of_records);
				break;
		}
	}


	Serial.println(F("-------------------------------------------------------------"));
}