/*
 * --------------------------------------------------------------------------------------------------------------------
 * Example sketch/program showing how to read data from a PICC to serial.
 * --------------------------------------------------------------------------------------------------------------------
 * This is a MFRC522 library example; for further details and other examples see: https://github.com/miguelbalboa/rfid
 * 
 * Example sketch/program showing how to read data from a PICC (that is: a RFID Tag or Card) using a MFRC522 based RFID
 * Reader on the Arduino SPI interface.
 * 
 * When the Arduino and the MFRC522 module are connected (see the pin layout below), load this sketch into Arduino IDE
 * then verify/compile and upload it. To see the output: use Tools, Serial Monitor of the IDE (hit Ctrl+Shft+M). When
 * you present a PICC (that is: a RFID Tag or Card) at reading distance of the MFRC522 Reader/PCD, the serial output
 * will show the ID/UID, type and any data blocks it can read. Note: you may see "Timeout in communication" messages
 * when removing the PICC from reading distance too early.
 * 
 * If your reader supports it, this sketch/program will read all the PICCs presented (that is: multiple tag reading).
 * So if you stack two or more PICCs on top of each other and present them to the reader, it will first output all
 * details of the first and then the next PICC. Note that this may take some time as all data blocks are dumped, so
 * keep the PICCs at reading distance until complete.
 * 
 * @license Released into the public domain.
 * 
 * Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 */

#include <SPI.h>
#include <MFRC522.h>
#include <Desfire.h>

#define RST_PIN         9          // Configurable, see typical pin layout above
#define SS_PIN          10         // Configurable, see typical pin layout above

DESFire mfrc522(SS_PIN, RST_PIN);  // Create MFRC522 instance

void setup() {
  Serial.begin(9600);   // Initialize serial communications with the PC
  while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();      // Init SPI bus
  mfrc522.PCD_Init();   // Init MFRC522
  mfrc522.PCD_DumpVersionToSerial();  // Show details of PCD - MFRC522 Card Reader details
  Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));
}

void loop() {
  // Look for new cards
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  if (mfrc522.uid.sak != 0x20) {
    // Dump debug info about the card; PICC_HaltA() is automatically called
    mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
    return;
  }

  // Show an extra line
  Serial.println();

  DESFire::mifare_desfire_tag tag;
  DESFire::StatusCode response;

  tag.pcb = 0x0A;
  tag.cid = 0x00;
  memset(tag.selected_application, 0, 3);

  // Make sure none DESFire status codes have DESFireStatus code to OK
  response.desfire = DESFire::MF_OPERATION_OK;
  
  byte ats[16];
  byte atsLength = 16;
  response.mfrc522 = mfrc522.PICC_RequestATS(ats, &atsLength);
  if ( ! mfrc522.IsStatusCodeOK(response)) {
    Serial.println(F("Failed to get ATS!"));
    Serial.println(mfrc522.GetStatusCodeName(response));
    Serial.println(response.mfrc522);
    
    mfrc522.PICC_HaltA();
    return;
  }

  // TODO: Should do checks but since I know my DESFire allows and requires PPS...
  //       PPS1 is ommitted and, therefore, 0x00 is used (106kBd)
  response.mfrc522 = mfrc522.PICC_ProtocolAndParameterSelection(0x00, 0x11);
  if ( ! mfrc522.IsStatusCodeOK(response)) {
    Serial.println(F("Failed to perform protocol and parameter selection (PPS)!"));
    Serial.println(mfrc522.GetStatusCodeName(response));
    mfrc522.PICC_HaltA();
    return;
  }

  // MIFARE DESFire should respond to a GetVersion command
  DESFire::MIFARE_DESFIRE_Version_t desfireVersion;
  response = mfrc522.MIFARE_DESFIRE_GetVersion(&tag, &desfireVersion);
  if ( ! mfrc522.IsStatusCodeOK(response)) {
    Serial.println(F("Failed to get a response for GetVersion!"));
    Serial.println(mfrc522.GetStatusCodeName(response));
    mfrc522.PICC_HaltA();
    return;
  }
  
  // Dump MIFARE DESFire version information.
  // NOTE: KEEP YOUR CARD CLOSE TO THE READER!
  //       This method takes some time and the card will be read
  //       once output ends! If you remove the card too fast
  //       a timeout will occur!
  mfrc522.PICC_DumpMifareDesfireVersion(&tag, &desfireVersion);

  mfrc522.PICC_DumpMifareDesfireMasterKey(&tag);

  DESFire::mifare_desfire_aid_t aids[MIFARE_MAX_APPLICATION_COUNT];
  byte applicationCount = 0;
  response = mfrc522.MIFARE_DESFIRE_GetApplicationIds(&tag, aids, &applicationCount);
  if ( ! mfrc522.IsStatusCodeOK(response)) {
    Serial.println(F("Failed to get application IDs!"));
    Serial.println(mfrc522.GetStatusCodeName(response));
    mfrc522.PICC_HaltA();
    return;
  }

  // Dump all applications
  for (byte aidIndex = 0; aidIndex < applicationCount; aidIndex++) {
    mfrc522.PICC_DumpMifareDesfireApplication(&tag, &(aids[aidIndex]));
  }
  
  // Call PICC_HaltA()
  mfrc522.PICC_HaltA();
  Serial.println();
}