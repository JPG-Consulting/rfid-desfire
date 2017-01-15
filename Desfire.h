#ifndef DESFIRE_h
#define DESFIRE_h

#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>

/* --------------------------------------
* DESFire Logical Structure
* --------------------------------------
*/
#define MIFARE_MAX_APPLICATION_COUNT 28 /* max applications on one PICC */
#define MIFARE_MAX_FILE_COUNT        16 /* max # of files in each application */
#define MIFARE_UID_BYTES             7  /* number of UID bytes */
#define MIFARE_AID_SIZE              3  /* number of AID bytes */

class DESFire : public MFRC522 {
public:
	// DESFire Status and Error Codes.
	enum DesfireStatusCode : byte {
		MF_OPERATION_OK          = 0x00,  /* successful operation */
		MF_NO_CHANGES            = 0x0C,  /* no changes done to backup files */
		MF_OUT_OF_EEPROM_ERROR   = 0x0E,  /* insufficient NV-Mem. to complete cmd */
		MF_ILLEGAL_COMMAND_CODE  = 0x1C,  /* command code not supported */
		MF_INTEGRITY_ERROR       = 0x1E,  /* CRC or MAC does not match data */
		MF_NO_SUCH_KEY           = 0x40,  /* invalid key number specified */
		MF_LENGTH_ERROR          = 0x7E,  /* length of command string invalid */
		MF_PERMISSION_ERROR      = 0x9D,  /* curr conf/status doesnt allow cmd */
		MF_PARAMETER_ERROR       = 0x9E,  /* value of the parameter(s) invalid */
		MF_APPLICATION_NOT_FOUND = 0xA0,  /* requested AID not present on PICC */
		MF_APPL_INTEGRITY_ERROR  = 0xA1,  /* unrecoverable err within app */
		MF_AUTHENTICATION_ERROR  = 0xAE,  /* cur auth status doesnt allow req cmd */
		MF_ADDITIONAL_FRAME      = 0xAF,  /* additional data frame to be sent */
		MF_BOUNDARY_ERROR        = 0xBE,  /* attempt to read/write beyond limits */
		MF_PICC_INTEGRITY_ERROR  = 0xC1,  /* unrecoverable error within PICC */
		MF_COMMAND_ABORTED       = 0xCA,  /* previous command not fully completed */
		MF_PICC_DISABLED_ERROR   = 0xCD,  /* PICC disabled by unrecoverable error */
		MF_COUNT_ERROR           = 0xCE,  /* cant create more apps, already @ 28 */
		MF_DUPLICATE_ERROR       = 0xDE,  /* cant create dup. file/app */
		MF_EEPROM_ERROR          = 0xEE,  /* couldnt complete NV-write operation */
		MF_FILE_NOT_FOUND        = 0xF0,  /* specified file number doesnt exist */
		MF_FILE_INTEGRITY_ERROR  = 0xF1   /* unrecoverable error within file */
	};

	// DESFire file types
	enum mifare_desfire_file_types : byte {
		MDFT_STANDARD_DATA_FILE = 0x00,
		MDFT_BACKUP_DATA_FILE = 0x01,
		MDFT_VALUE_FILE_WITH_BACKUP = 0x02,
		MDFT_LINEAR_RECORD_FILE_WITH_BACKUP = 0x03,
		MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP = 0x04
	};

	// DESFire communication modes
	enum mifare_desfire_communication_modes : byte {
		MDCM_PLAIN      = 0x00,    /* Plain Communication */
		MDCM_MACED      = 0x01,    /* Plain Comm secured by DES/3DES MACing */
		MDCM_ENCIPHERED = 0x03    /* Fully DES/3DES enciphered comm. */
	};

	// A struct used for passing a MIFARE DESFire Version 
	typedef struct {
		struct {
			uint8_t vendor_id;
			uint8_t type;
			uint8_t subtype;
			uint8_t version_major;
			uint8_t version_minor;
			uint8_t storage_size;
			uint8_t protocol;
		} hardware;

		struct {
			uint8_t vendor_id;
			uint8_t type;
			uint8_t subtype;
			uint8_t version_major;
			uint8_t version_minor;
			uint8_t storage_size;
			uint8_t protocol;
		} software;

		uint8_t uid[7];
		uint8_t batch_number[5];
		uint8_t production_week;
		uint8_t production_year;
	} MIFARE_DESFIRE_Version_t;

	typedef struct {
		uint8_t data[MIFARE_AID_SIZE];
	} mifare_desfire_aid_t;

	typedef struct {
		MFRC522::StatusCode mfrc522;
		DesfireStatusCode   desfire;
	} StatusCode;

	// A struct used for passing a MIFARE DESFire Version 
	typedef struct {
		uint8_t file_type;
		uint8_t communication_settings;
		uint16_t access_rights;

		union {
			struct {
				uint32_t file_size;
			} standard_file;
			struct {
				int32_t lower_limit;
				int32_t upper_limit;
				int32_t limited_credit_value;
				uint8_t limited_credit_enabled;
			} value_file;
			struct {
				uint32_t record_size;
				uint32_t max_number_of_records;
				uint32_t current_number_of_records;
			} record_file;                        /* linear and cyclic record files */
		} settings;
	} mifare_desfire_file_settings_t;

	typedef struct {
		byte cid;	// Card ID
		byte pcb;	// Protocol Control Byte
		byte selected_application[MIFARE_AID_SIZE];
	} mifare_desfire_tag;

	/////////////////////////////////////////////////////////////////////////////////////
	// Functions for setting up the Arduino
	/////////////////////////////////////////////////////////////////////////////////////
	explicit DESFire() : MFRC522() {};
	explicit DESFire(byte resetPowerDownPin) : MFRC522(resetPowerDownPin) {};
	explicit DESFire(byte chipSelectPin, byte resetPowerDownPin) : MFRC522(chipSelectPin, resetPowerDownPin) {};

	/////////////////////////////////////////////////////////////////////////////////////
	// ISO/IEC 14443 functions not currentlly present in MFRC522 library
	/////////////////////////////////////////////////////////////////////////////////////
	MFRC522::StatusCode PICC_RequestATS(byte *atsBuffer, byte *atsLength);
	MFRC522::StatusCode PICC_ProtocolAndParameterSelection(byte cid, byte pps0, byte pps1 = 0x00);

	/////////////////////////////////////////////////////////////////////////////////////
	// Functions for MIFARE DESFire
	/////////////////////////////////////////////////////////////////////////////////////
	StatusCode MIFARE_DESFIRE_GetVersion(mifare_desfire_tag *tag, MIFARE_DESFIRE_Version_t *versionInfo);
	StatusCode MIFARE_DESFIRE_GetApplicationIds(mifare_desfire_tag *tag, mifare_desfire_aid_t *aids, byte *applicationCount);
	StatusCode MIFARE_DESFIRE_SelectApplication(mifare_desfire_tag *tag, mifare_desfire_aid_t *aid);
	StatusCode MIFARE_DESFIRE_GetKeySettings(mifare_desfire_tag *tag, byte *settings, byte *maxKeys);
	StatusCode MIFARE_DESFIRE_GetKeyVersion(mifare_desfire_tag *tag, byte key, byte *version);

	/////////////////////////////////////////////////////////////////////////////////////
	// MIFARE DESFire application level commands
	/////////////////////////////////////////////////////////////////////////////////////
	StatusCode MIFARE_DESFIRE_GetFileIDs(mifare_desfire_tag *tag, byte *files, byte *filesCount);
	StatusCode MIFARE_DESFIRE_GetFileSettings(mifare_desfire_tag *tag, byte *file, mifare_desfire_file_settings_t *fileSettings);

	/////////////////////////////////////////////////////////////////////////////////////
	// MIFARE DESFire data manipulation commands
	/////////////////////////////////////////////////////////////////////////////////////
	StatusCode MIFARE_DESFIRE_ReadData(mifare_desfire_tag *tag, byte fid, uint32_t offset, uint32_t length, byte *backData, size_t *backLen);
	StatusCode MIFARE_DESFIRE_GetValue(mifare_desfire_tag *tag, byte fid, int32_t *value);

	/////////////////////////////////////////////////////////////////////////////////////
	// Support functions
	/////////////////////////////////////////////////////////////////////////////////////
	static const __FlashStringHelper *GetDesfireStatusCodeName(DesfireStatusCode code);
	virtual const __FlashStringHelper *GetStatusCodeName(MFRC522::StatusCode code) { return MFRC522::GetStatusCodeName(code);  };
	static const __FlashStringHelper *GetStatusCodeName(StatusCode code);
	static const __FlashStringHelper *GetFileTypeName(mifare_desfire_file_types fileType);
	static const __FlashStringHelper *GetCommunicationModeName(mifare_desfire_communication_modes communicationMode);
	bool IsStatusCodeOK(StatusCode code);

	/////////////////////////////////////////////////////////////////////////////////////
	// Functions for debugging
	/////////////////////////////////////////////////////////////////////////////////////
	void PICC_DumpMifareDesfireMasterKey(mifare_desfire_tag *tag);
	void PICC_DumpMifareDesfireVersion(mifare_desfire_tag *tag, MIFARE_DESFIRE_Version_t *versionInfo);
	void PICC_DumpMifareDesfireApplication(mifare_desfire_tag *tag, mifare_desfire_aid_t *aid);

protected:
	/////////////////////////////////////////////////////////////////////////////////////
	// Helper methods
	/////////////////////////////////////////////////////////////////////////////////////
	StatusCode MIFARE_BlockExchange(mifare_desfire_tag *tag, byte cmd, byte *backData = NULL, byte *backLen = NULL);
	StatusCode MIFARE_BlockExchangeWithData(mifare_desfire_tag *tag, byte cmd, byte *sendData = NULL, byte *sendLen = NULL, byte *backData = NULL, byte *backLen = NULL);
};

#endif