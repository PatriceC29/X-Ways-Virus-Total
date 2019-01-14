///////////////////////////////////////////////////////////////////////////////
// X-Tension API - template for new X-Tensions
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "../XT_Main/X-Tension.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <string.h>
#include <string>
#include <curl/curl.h>
#include <json/json.h>
#include <locale>
#include <codecvt>

// value used to check the number of 
int numIt = 0;

// add HERE code to send request in VirusTotal
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
}

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation


std::wstring utf8_to_utf16(const std::string& utf8)
{
	std::vector<unsigned long> unicode;
	size_t i = 0;
	while (i < utf8.size())
	{
		unsigned long uni;
		size_t todo;
		bool error = false;
		unsigned char ch = utf8[i++];
		if (ch <= 0x7F)
		{
			uni = ch;
			todo = 0;
		}
		else if (ch <= 0xBF)
		{
			throw std::logic_error("not a UTF-8 string");
		}
		else if (ch <= 0xDF)
		{
			uni = ch & 0x1F;
			todo = 1;
		}
		else if (ch <= 0xEF)
		{
			uni = ch & 0x0F;
			todo = 2;
		}
		else if (ch <= 0xF7)
		{
			uni = ch & 0x07;
			todo = 3;
		}
		else
		{
			throw std::logic_error("not a UTF-8 string");
		}
		for (size_t j = 0; j < todo; ++j)
		{
			if (i == utf8.size())
				throw std::logic_error("not a UTF-8 string");
			unsigned char ch = utf8[i++];
			if (ch < 0x80 || ch > 0xBF)
				throw std::logic_error("not a UTF-8 string");
			uni <<= 6;
			uni += ch & 0x3F;
		}
		if (uni >= 0xD800 && uni <= 0xDFFF)
			throw std::logic_error("not a UTF-8 string");
		if (uni > 0x10FFFF)
			throw std::logic_error("not a UTF-8 string");
		unicode.push_back(uni);
	}
	std::wstring utf16;
	for (size_t i = 0; i < unicode.size(); ++i)
	{
		unsigned long uni = unicode[i];
		if (uni <= 0xFFFF)
		{
			utf16 += (wchar_t)uni;
		}
		else
		{
			uni -= 0x10000;
			utf16 += (wchar_t)((uni >> 10) + 0xD800);
			utf16 += (wchar_t)((uni & 0x3FF) + 0xDC00);
		}
	}
	return utf16;
}


///////////////////////////////////////////////////////////////////////////////
// XT_Init
LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd,
	void* lpReserved)
{
	XT_RetrieveFunctionPointers();
	XWF_OutputMessage(L"> TombFinder_V2x64", 0);
	XWF_OutputMessage(L"> This extension record the hash file/list (MD5/SHA1),", 0);
	XWF_OutputMessage(L"> And check the score of file(s) in VirusTotal.", 0);
	XWF_OutputMessage(L"> /!\\ Hash1 can be a MD5, Hash2 can be a SHA1 /!\\", 0);

	/******************* For public X-Tension ********************/
	// init ifstream, and give the conf file
	ifstream infile;
	infile.open("conf.ini");

	// check if the file is open
	if (!infile) {
		XWF_OutputMessage(L"[!] Could not open file.", 0);
		return -1;
	}
	infile.close();
	
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About
LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved) {
	XWF_OutputMessage(L"--==[ Created by D2A ]==--", 0);
	XWF_OutputMessage(L"[ Developped by Icenuke ]", 0);
	
	//XWF_OutputMessage(L"ABOUT", 0);
		
	return 0;
}


//LONG _stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, PVOID lpReserved) 
//{
//	hVol = hVolume;
//	return 0;
//}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItemEx
// 1) record name item
// 2) record hash value
// 3) convert hashBuf in string stream
// 4) send request to VirusTotal
// 5) record and parse information from VirusTotal
// 5) add information in file
LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved)
{
	//////////////////////////////////////////
	//										//
	//			File information record		//
	//										//
	//////////////////////////////////////////
	
	// check if the number of request is not in max
	numIt++;
	if (numIt == 5) {
		XWF_OutputMessage(L"[!] NUMBER OF REQUEST REACHED!!", 0);
		return -1;
	}
	/********************* For public X-Tension *************************/
	// init ifstream, and give the conf file
	ifstream infile;
	infile.open("conf.ini");

	// check if the file is open
	if (!infile) {
		XWF_OutputMessage(L"[!] Could not open file.", 0);
		return -1;
	}

	// you only need one word at a time.
	string word;
	string apiKey;

	// init cpt,, and iter in all word
	int i = 1;
	while (infile >> word) {
		// record apikey path
		if (i == 2) {
			apiKey = word;
		}
		i += 1;
	}
	infile.close();

	// check the length of the apiKey and exReport string
	// if the lengths are too small then return -1 to precise in xWays to stop operation
	if (apiKey.length() < 64) {
		apiKey = "None";
		XWF_OutputMessage(L"[!] Bad ApiKey!", 0);
		return -1;
	}

	//////////////////////////////////////////
	//										//
	//			information record			//
	//										//
	//////////////////////////////////////////

	// Declare name file and add this in wstr
	wstring name = XWF_GetItemName(nItemID);

	// print in console the record item information
	wstring printing = L"[+] Record ";
	printing += name;
	printing += L" information.";
	XWF_OutputMessage(printing.c_str(), 0);

	// convert name wstr in string and add this in name string
	string nameStr(name.begin(), name.end());
	string nameItm;
	nameItm = "[+] ";
	nameItm += nameStr;
	nameItm += "\n";

	/********************************** SHA1 ******************************/
	// print in console hash info recording
	XWF_OutputMessage(L"[+] Record Hash SHA1.", 0);

	// declare hash buffer and the flag for the GETHASHVALUE
	BYTE hashBuf[512] = { 0 };
	BYTE value = 0x02;
	hashBuf[0] = value;
	hashBuf[1] = 0x0;

	// declare check value, size
	int check = sizeof(HANDLE);
	memcpy(&hashBuf[4], &hItem, check);

	// call GetHashValue return bool -1 if record ok
	BOOL hash = XWF_GetHashValue(nItemID, hashBuf);

	// declare HashVal 
	//string hashVal = ">> Hash SHA1 Value:\n";
	string hashVal = ">> Hash SHA1 du fichier:\n";

	/*********************************************************************/
	/***************************** MD5 ***********************************/

	XWF_OutputMessage(L"[+] Record Hash MD5.", 0);
	// declare hash buffer and the flag for the GETHASHVALUE
	BYTE MD5Buf[512] = { 0 };
	BYTE vals = 0x01;
	MD5Buf[0] = vals;
	MD5Buf[1] = 0x0;

	// declare check value, size
	int checkMD = sizeof(HANDLE);
	memcpy(&MD5Buf[4], &hItem, checkMD);

	// call GetHashValue return bool -1 if record ok
	BOOL MD5 = XWF_GetHashValue(nItemID, MD5Buf);

	// declare HashVal 
	//string MD5Val = ">> Hash MD5 Value:\n";
	string MD5Val = ">> Hash MD5 du fichier:\n";
	/*********************************************************************/
	/********************** Convert hash in str **************************/
	// declare the string stream to record the hexadecimal value of hashBuf (SHA1)
	stringstream strStream;
	strStream << hex;
	for (int i = 0; i < 20; ++i) {
		strStream << setw(2) << setfill('0') << (int)hashBuf[i];
	}

	// declare the string stream to record the hexadecimal value of MD5Buf (MD5)
	stringstream strMD5;
	strMD5 << hex;
	for (int i = 0; i < 16; ++i) {
		strMD5 << setw(2) << setfill('0') << (int)MD5Buf[i];
	}

	//////////////////////////////////////////
	//										//
	//			Communication with VT		//
	//										//
	//////////////////////////////////////////

	// print init connection
	XWF_OutputMessage(L"[+] Connection Initialization.", 0);

	// init curl pointer and result
	CURL *curl;
	//CURLcode result;

	// init the curl winsock stuff
	curl_global_init(CURL_GLOBAL_ALL);

	// get a curl handle
	curl = curl_easy_init();
	if (curl) {
		// print init connection ok
		XWF_OutputMessage(L"[+] initialization succed!", 0);
		XWF_OutputMessage(L"[+] Start send hash!", 0);

		// string apiKey = "a34c4261b57f6a61bf61b75b763be89cbad351d0be637822bc35b6ead6c053a8";

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

		// Perform the request, res will get the return code
		//result = 
		curl_easy_perform(curl);
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
		// always cleanup
		curl_easy_cleanup(curl);

		// check if the response code is 200
		if (httpCode == 200) {
			XWF_OutputMessage(L"[+] Response succed!", 0);

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
				XWF_OutputMessage(L"[+] Start parsing JSON report.", 0);
				// record total value and positives value if exist
				string total(jsonData["total"].asString());
				string positives(jsonData["positives"].asString());
				int positivesTest(jsonData["positives"].asInt());

				//string scoring = ">> VirusTotal Scoring:\n";
				string scoring = ">> Score VirusTotal:\n";
				string strScore;

				DWORD flagsCom = 0x01;

				//string rdBuff;

				// check if total and empty are empty
				if (total.empty() && positives.empty()) {
					// if no score then add information in var
					//strScore = "No Score for this file!!";
					strScore = "Pas de résultat pour ce fichier!!";
					XWF_OutputMessage(L"[!] No Score for this file", 0);
				
				}
				else {
					// if score exist then add it in var
					strScore = positives + "/" + total;
				}

				// prepare the string for the convertion
				wstring wsScore = utf8_to_utf16(strScore);
				
				wchar_t * wcScore = &wsScore[0];

				XWF_OutputMessage(L"[+] Virustotal Scoring:", 0);
				XWF_OutputMessage(wsScore.c_str(), 0);


				XWF_AddComment(nItemID, wcScore, flagsCom);
				
				//////////////////////////////////////////
				//										//
				//			Creation report file		//
				//										//
				//////////////////////////////////////////

				// Record the size of the file
				string sizeStr = ">> Bytes Size:\n";
				string size = to_string(XWF_GetSize(hItem, (LPVOID)1)) + " Bytes!";

				// open/create file report in append mode
				//ofstream reportFile("export/reportXtension.txt", ios::app);
				ofstream reportFile("reportXTension.txt", ios::app);
				// add lines information
				reportFile << nameItm;
				reportFile << MD5Val;
				reportFile << strMD5.str();
				reportFile << "\n";
				reportFile << hashVal;
				reportFile << strStream.str();
				reportFile << "\n";
				reportFile << scoring;
				reportFile << strScore;
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
				strScore.clear();
				//wsScore.clear();
				

				// print in console the information adding in file
				XWF_OutputMessage(L"[+] Information added in file \"reportXtension.txt\".", 0);
				XWF_OutputMessage(L"[+] Finish with success!!", 0);
				// global cleanup
				curl_global_cleanup();

			}else {
				XWF_OutputMessage(L"[!] Failled to record the JSON data to parse this.", 0);
				return -1;
			}
		}else {
			XWF_OutputMessage(L"[+] Bad Response Code!", 0);
			// global cleanup
			curl_global_cleanup();
		}
	}else {
		XWF_OutputMessage(L"[!] Problem with the connection!", 0);
		// global cleanup
		curl_global_cleanup();
		return -1;
	}

	// end of function
	// function reloaded if many file selectioned
	return 0;
}
