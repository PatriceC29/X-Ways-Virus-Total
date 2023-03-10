///////////////////////////////////////////////////////////////////////////////
// X-Tension using VirusTotal API
// Copyright 2023 Patrice Couillon
///////////////////////////////////////////////////////////////////////////////
// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

#include "X-Vt.h"
#include "../XT_Main/X-Tension.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <string>
#include <curl/curl.h>
#include <json/json.h>
#include <locale>
#include <codecvt>
#include <windows.h>

//const int XWF_VSPROP_HASHTYPE1 = 20;
//const int XWF_VSPROP_HASHTYPE2 = 21;
//const int HASH_SIZE = 20; //size in bystes of SHA-1 hash
// values used to check the number of iterations
int numIt = 0;
int nbItems = 0;
int nbItemsSet = 0;

// which hash is SHA-1
int sha = 0;
int sha1 = 0;
int shadone = 0;

using namespace std;
namespace
{
	std::size_t callback(
		const char* in,
		std::size_t size,
		std::size_t num,
		std::string* out)
	{
		const std::size_t totalBytes(size * num);
		out->append(in, totalBytes);
		return totalBytes;
	}

	//////////////////////////////////////////////////////////////////////////////
	//Callback function for response header  -- x-api-message -- Curl
	static std::size_t header_callback(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
		std::string header(buffer, size * nitems);
		std::size_t colon_pos = header.find(':');
		if (colon_pos != std::string::npos) {
			std::string header_name = header.substr(0, colon_pos);
			std::string header_value = header.substr(colon_pos + 1);
			// Trim leading and trailing white space from header value
			header_value = header_value.erase(0, header_value.find_first_not_of(" \t\r\n"));
			header_value = header_value.erase(header_value.find_last_not_of(" \t\r\n") + 1);
			if (header_name == "X-Api-Message") {
				*static_cast<std::string*>(userdata) = header_value;
			}
		}
		return nitems * size;
	}

	// Function to check if the result is SHA-1 or not and return the hash string
	string checkHash(int result, int shatest) {
		if (result == 8) {
			sha1++;
			sha = shatest;
			return "SHA-1";
		}
		else {
			return "Not SHA-1";
		}
	}

}


///////////////////////////////////////////////////////////////////////////////
// XT_Init
LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd,
	void* lpReserved)
{
	XT_RetrieveFunctionPointers();
	XWF_OutputMessage(L"> VirusTotal Hash X-Tension", 0);

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About
LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved) {

	const wchar_t* constMessage =	L"VirusTotal X-Tension For X-Ways\n\n"
									L"Gets Score of a given file sending it's SHA-1 hash.\n"
									L"No files are sent.\n\n"
									L"Rewritten and enhanced by :\n"
									L"Patrice C. (SDLC/Formation)\n"
									L"Original idea  : SDLC/D2A\n";

	wchar_t* message = const_cast<wchar_t*>(constMessage);

	const wchar_t* constTitle = L"About VirusTotal X-Tension";
	wchar_t* title= const_cast<wchar_t*>(constTitle);

	MessageBox(NULL, message, title, MB_OK);
	
	return 0;
}

// Exported function called by X-Ways when preparing for operations and to determine how we are to be called going forward
LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved) {

	// Only run when refining the volume snapshot or when invoked via the directory browser context menu
	if (nOpType == XT_ACTION_RUN || nOpType == XT_ACTION_RVS || nOpType == XT_ACTION_DBC) {
		return XT_PREPARE_CALLPI;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItemEx
// 1) retrieve item name
// 2) retrieve hash value
// 3) convert hashBuf into string stream
// 4) send request to VirusTotal
// 5) retrieve and parse response from VirusTotal
// 5) add information in report file
LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved)
{
	//////////////////////////////////////////
	//										//
	//		         Setup                  //
	//										//
	//////////////////////////////////////////
	

	// Parsing INI file : .\config.ini
	// Getting the API Key and the type of key

	char iniKey[65];

	GetPrivateProfileStringA("config", "apikey", "", iniKey, 65,  ".\\config.ini");

	std::string apiKey(iniKey);
	
	// checks the length of the apiKey 
	// if the length is too small then returns -1 to tell X-Ways to abort process
	if (apiKey.length() < 64) {

		std::wstring uAK = std::wstring(apiKey.begin(), apiKey.end());
		const wchar_t* AK = uAK.c_str();
		std::wstring errAK = L"[!] Bad ApiKey : ";
		errAK += AK;
	
		XWF_OutputMessage(errAK.c_str(), 0);

		return -1;
	}
	
	int kType = GetPrivateProfileIntA("config", "public", 0, ".\\config.ini");
	if (kType == 1) {
		XWF_OutputMessage(L"[+] Using public key", 0);

	}
	else {
		XWF_OutputMessage(L"[+] Using paid key.", 0);
	}

	// Nb Items -- For X-Ways 20.3 SR3 and later
	if (nbItemsSet == 0) {
		nbItems = XWF_GetItemCount((LPVOID)1);
		std::string nbI = "[+] Items : ";
		nbI += std::to_string(nbItems);
		std::wstring items = std::wstring(nbI.begin(), nbI.end());
		XWF_OutputMessage(items.c_str(), 0);
		nbItemsSet++;
	}
	

	// Hash types detection

	// -- Hash Types --
	int hashType = 0;
	
	if (shadone < 1) {
		// First hash
		string hash1 = checkHash(XWF_GetVSProp(XWF_VSPROP_HASHTYPE1, &hashType),  1);

		// Second hash
		string hash2 = checkHash(XWF_GetVSProp(XWF_VSPROP_HASHTYPE2, &hashType),  2);

		shadone++;

		// Output
		std::wostringstream output;
		output << L"[+] Hash Types : hash1 : " << std::wstring(hash1.begin(), hash1.end()) << L", hash2 : " << std::wstring(hash2.begin(), hash2.end());
		XWF_OutputMessage(output.str().c_str(), 0);

		if (sha1 < 1)
		{
			XWF_OutputMessage(L"No SHA-1 hash available", 0);
			return -1;
		}

	}

	
	//////////////////////////////////////////
	//										//
	//			Item's informations 		//
	//										//
	//////////////////////////////////////////

	// Declare name file and add this in wstr
	wstring name = XWF_GetItemName(nItemID);

	// convert name wstr in string and add this in name string
	string nameStr(name.begin(), name.end());
	string nameItm;
	nameItm = "[+] ";
	nameItm += nameStr;
	nameItm += "\n";

	/********************************** SHA1 ******************************/
	// print in console hash info recording

	BOOL bResult = FALSE;
	
	BYTE* pBuffer = new BYTE[HASH_SIZE + sizeof(DWORD) + sizeof(HANDLE)]; // allocate buffer with room for hash value, DWORD flag, and handle

	// Set the flag to retrieve the hash value and compute it if missing
	// 
	*(DWORD*)pBuffer = (sha == 1) ? 0x11 : 0x12;

	*(HANDLE*)(pBuffer + sizeof(DWORD)) = hItem; // set handle at buffer offset after DWORD flag

	// Call XWF_GetHashValue to retrieve the hash value and compute it if missing
	bResult = XWF_GetHashValue(nItemID, pBuffer);

	stringstream strStream;
	strStream << hex;
	for (int i = 0; i < 20; ++i) {
		strStream << setw(2) << setfill('0') << (int)pBuffer[i];
	}

	// free the allocated buffer
	delete[] pBuffer;

	string hashVal = ">> Hash SHA1 of :\n";


	//////////////////////////////////////////
	//										//
	//			Communication with VT		//
	//										//
	//////////////////////////////////////////

	// print init connection
	XWF_OutputMessage(L"[+] Connecting...", 0);

	// init curl pointer and result
	CURL *curl;
	
	// init the curl winsock stuff
	curl_global_init(CURL_GLOBAL_ALL);

	// get a curl handle
	curl = curl_easy_init();
	if (curl) {

		wstring sending = L"[+] Sending hash of : ";
		sending += name;

		XWF_OutputMessage(sending.c_str(), 0);

		// set the URL that is about to receive our POST.
		string urlScan = "https://www.virustotal.com/vtapi/v2/file/report?apikey=";
		urlScan += apiKey;
		urlScan += "&resource=";
		urlScan += strStream.str();
		/***************************************************/
		/* /!\ DON'T FORGET THE .c_str() AFTER URLSCAN /!\ */
		/***************************************************/
		curl_easy_setopt(curl, CURLOPT_URL, urlScan.c_str());

		// accept ssl
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

		
		int httpCode(0);
		std::unique_ptr<std::string> httpData(new std::string());

		// Hook up data handling function.
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);

		// Hook up data container (will be passed as the last parameter to the
		// callback handling function).  Can be any pointer type, since it will
		// internally be passed as a void pointer.
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

		//--- Case of HTTP 204 : maximum queries reached
		std::string x_api_message;
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &x_api_message);

		// Perform the request, res will get the return code
		curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
		// always cleanup
		curl_easy_cleanup(curl);

		if (httpCode == 403) {
			XWF_OutputMessage(L"[!] Error : Access denied. ", 0);
			XWF_OutputMessage(L"[!] Check API key in config.ini ", 0);
			return -1;
		}

		if (httpCode == 204) {
			std::wstring api_message = std::wstring(x_api_message.begin(), x_api_message.end());
			const wchar_t* apiMessage = api_message.c_str();
			
			XWF_OutputMessage(L"[!] Error : HTTP 204 ", 0);
			XWF_OutputMessage(apiMessage, 0);

			return -1;
		}


		// check if the response code is 200
		if (httpCode == 200) {
			XWF_OutputMessage(L"[+] Response : OK !", 0);

			
			//////////////////////////////////////////
			//										//
			//			Parsing Report VT			//
			//										//
			//////////////////////////////////////////

			// Response looks good - done using Curl now.  Try to parse the results
			// and print them out.
			Json::Value jsonData;
			Json::Reader jsonReader;

			// try to record json data
			if (jsonReader.parse(*httpData, jsonData))
			{
				ofstream dataFile("data.json", ios::trunc);
				dataFile << jsonData;
				dataFile.close();

				// XWF_OutputMessage(L"[+] Parsing JSON response.", 0);
				// record total value and positives value if exist
				string total(jsonData["total"].asString());
				string positives(jsonData["positives"].asString());

				int posInt(jsonData["positives"].asInt());

				int minscore = GetPrivateProfileIntA("config", "minscore", 0, ".\\config.ini");
				if (posInt >= minscore) {

					DWORD flagrt = 0x01;

					const wchar_t* constRTName = L"VirusTotal";
					wchar_t* tableName = const_cast<wchar_t*>(constRTName);
					
					XWF_OutputMessage(L"[+] Added to report table.", 0);
					LONG rtIndex = XWF_AddToReportTable(nItemID, tableName, flagrt);
				}

				string scoring = ">> Score VirusTotal:\n";
				wstring wstrScore;

				DWORD flagsCom = 0x01;

				// check if total and positives are empty
				if (total.empty() && positives.empty()) {

					wstrScore = L"0/0";
					XWF_OutputMessage(L"[!] No Score for this file", 0);
				
				}
				else {
					// if score exist then add it in var

					std::wstring wpositives = std::wstring(positives.begin(), positives.end());
					std::wstring wtotal = std::wstring(total.begin(), total.end());

					wstrScore = wpositives + L"/" + wtotal;
				}


				wchar_t * wcScore = &wstrScore[0];

				XWF_OutputMessage(L"[+] VirusTotal Score:", 0);
				XWF_OutputMessage(wstrScore.c_str(), 0);


				XWF_AddComment(nItemID, wcScore, flagsCom);
				
				//////////////////////////////////////////
				//										//
				//			Report file		            //
				//										//
				//////////////////////////////////////////

				// Size of the file
				string sizeStr = ">> Bytes Size:\n";
				string size = to_string(XWF_GetSize(hItem, (LPVOID)1)) + " Bytes";

				// open/create report file in append mode
				ofstream reportFile("reportXTension.txt", ios::app);
				// add informations
				reportFile << nameItm;
				reportFile << "\n";
				reportFile << hashVal;
				reportFile << strStream.str();
				reportFile << "\n";
				reportFile << scoring;

				std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
				std::string score = converter.to_bytes(wstrScore);
				reportFile << score;
				reportFile << "\n";
				reportFile << sizeStr;
				reportFile << size;
				reportFile << "\n\n";
				// close file
				reportFile.close();

				// Clean variables
				nameStr.clear();
				hashVal.clear();
				total.clear();
				positives.clear();
				wstrScore.clear();
				
				XWF_OutputMessage(L"[+] Informations added to report \"reportXtension.txt\".", 0);
				// global cleanup
				curl_global_cleanup();

			}else {
				XWF_OutputMessage(L"[!] Failled to parse JSON response.", 0);
				return -1;
			}
		}else {
			// Error with HTTP response code if response code not 200, 204 or 403
			std::wostringstream resp;
			resp << "[!] Bad Response Code! : " << httpCode;
			std::wstring responseStr = resp.str(); // Store the result of resp.str() in a variable
			const wchar_t* responsec = responseStr.c_str(); // Use the c_str() method on the stored variable

			XWF_OutputMessage(responsec, 0);

			std::wostringstream uResp;
			std::wstring urlScanW = std::wstring(urlScan.begin(), urlScan.end()); // Convert urlScan to a wstring
			uResp << "[!] URL : " << urlScanW;
			std::wstring uResponseStr = uResp.str();
			const wchar_t* uResponsec = uResponseStr.c_str();

			XWF_OutputMessage(uResponsec, 0);
			
			// global cleanup
			curl_global_cleanup();
		}
	}else {
		XWF_OutputMessage(L"[!] Problem connecting !", 0);
		// global cleanup
		curl_global_cleanup();
		return -1;
	}

	// end of function
	// function reloaded if multiple files selected
	
	nbItems--;
	if (nbItems > 0) {
		if (kType == 1)	{
			// Wait 15s between queries if public key
			XWF_OutputMessage(L"- - 15s delay between queries... (Public API key)", 0);
			Sleep(15000);
		}
		numIt++;	
	}

	if (nbItems == 0) {
		XWF_OutputMessage(L"-- Operation Completed --", 0);
	}

	return 0;
}
