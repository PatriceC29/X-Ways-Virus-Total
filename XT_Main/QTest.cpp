///////////////////////////////////////////////////////////////////////////////
// X-Tension API - template for new X-Tensions
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "X-Tension.h"

#include <string.h>

// adds 100 kB to the executable ...
#include <string>
using namespace std;

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

///////////////////////////////////////////////////////////////////////////////
// XT_Init

int missingFuncs;

void testFunc(void* func, const wchar_t* fname)
{
	wchar_t buf[256];
	if (func == NULL) {
		wcscpy_s(buf, L"Missing function : ");
		wcscat_s(buf, fname);
		XWF_OutputMessage (buf, 0);
		++missingFuncs;
	}
}

LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd,
   void* lpReserved)
{
   XT_RetrieveFunctionPointers();
	missingFuncs = 0;

	testFunc(XWF_GetBlock, L"XWF_GetBlock");
	testFunc(XWF_SetBlock, L"XWF_SetBlock");
	testFunc(XWF_GetCaseProp, L"XWF_GetCaseProp");
	testFunc(XWF_GetFirstEvObj, L"XWF_GetFirstEvObj");
	testFunc(XWF_GetNextEvObj, L"XWF_GetNextEvObj");
	testFunc(XWF_OpenEvObj, L"XWF_OpenEvObj");
	testFunc(XWF_CloseEvObj, L"XWF_CloseEvObj");
	testFunc(XWF_GetEvObjProp, L"XWF_GetEvObjProp");
	testFunc(XWF_GetExtractedMetadata, L"XWF_GetExtractedMetadata");
	testFunc(XWF_GetMetadataEx, L"XWF_GetMetadataEx");
	testFunc(XWF_AddExtractedMetadata, L"XWF_AddExtractedMetadata");
	testFunc(XWF_GetHashValue, L"XWF_GetHashValue");
	testFunc(XWF_AddEvent, L"XWF_AddEvent");

	wchar_t buf[256], num[20];
	_itow_s(missingFuncs, num, 10);
	wcscpy_s(buf, L"XT_QTest initialized - "	);
	wcscat_s(buf, num);
	wcscat_s(buf, L" missing functions");
	XWF_OutputMessage (buf, 0);

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Done

LONG __stdcall XT_Done(void* lpReserved)
{
	XWF_OutputMessage(L"XT_QTest done", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About

LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved)
{
	XWF_OutputMessage (L"XT_QTest about", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, 
   void* lpReserved)
{
	XWF_OutputMessage(L"X-Tension prepare", 0);

	wchar_t buf[256];
	XWF_GetVolumeName(hVolume, buf, 1);

	LONG fileSystem;
	DWORD bytesPerSector, sectorsPerCluster;
	INT64 clusterCount, firstCluster;
	XWF_GetVolumeInformation(hVolume, &fileSystem, &bytesPerSector, &sectorsPerCluster, 
		&clusterCount, &firstCluster);

	wstring str = L"Dancing with ";
	str += buf;

	INT64 size = XWF_GetProp(hVolume, 0, nullptr);

	wchar_t sizeStr[20], countStr[20];
	_i64tow_s(size, sizeStr, 20, 10);
	str += L", ";
	str += sizeStr;
	str += L" MB, ";
	auto count = XWF_GetItemCount(hVolume);
	_i64tow_s(count, countStr, 20, 10);
	str += countStr;
	str += L" items";

	XWF_OutputMessage (str.c_str(), 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Finalize

LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType,
	void* lpReserved)
{
	XWF_OutputMessage(L"XT_QTest finalize", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItem

LONG __stdcall XT_ProcessItem(LONG nItemID, void* lpReserved)
{
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItemEx

LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved)
{
	BYTE buf[512];
	INT64 offset = 0;
	auto read = XWF_Read(hItem, offset, buf, sizeof(buf));

	if (read == sizeof(buf)) {
		if ((buf[0] = 'B' && buf[1] == 'M')
		||  (buf[0] = 0xff && buf[1] == 0xd8))
		{
			 XWF_AddComment(nItemID, L"Hey, look, a picture!", 0);
		}
	}

	// Leads to a crash in WinHex for filenames that exceed MAX_PATH
	wstring str;
	auto num = XWF_GetItemSize(nItemID);
	str = XWF_GetItemName(nItemID);
	str += L" ";
	str += to_wstring(num);
	str += L" bytes";
	XWF_OutputMessage (str.c_str(), 0);

	// Also leads to a crash in WinHex...
	/*wchar_t str[1024], numStr[20];
	INT64 num = XWF_GetItemSize(nItemID).QuadPart;
	wcscpy_s(str, XWF_GetItemName(nItemID));
	wcscat_s(str, L" ");
	_i64tow_s(num, numStr, 20, 10);
	wcscat_s(str, numStr);
	wcscat_s(str, L" bytes");
	XWF_OutputMessage (str, 0);

	// This does not crash WinHex, but it slows down very much
	//const wchar_t* fn = XWF_GetItemName(nItemID);
	//XWF_OutputMessage (fn, 0);

	/*auto size1 = XWF_GetItemSize(nItemID);
	auto size2 = XWF_GetSize(hItem, NULL);
	if (size1 != size2 || nItemID % 100 == 0) {
		wchar_t str[1024], size1Str[20], size2Str[20];
		wcscpy_s(str, L"Deviant sizes for ");
		wcscat_s(str, XWF_GetItemName(nItemID));
		wcscat_s(str, L": ");
		_i64tow_s(size1, size1Str, 20, 10);
		wcscat_s(str, size1Str);
		wcscat_s(str, L" bytes vs ");
		_i64tow_s(size2, size2Str, 20, 10);
		wcscat_s(str, size2Str);
		wcscat_s(str, L" bytes");
		XWF_OutputMessage (str, 0);
	}*/
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessSearchHit

#pragma pack(2)
struct SearchHitInfo {
	LONG iSize;
	LONG nItemID;
	LARGE_INTEGER nRelOfs;
	LARGE_INTEGER nAbsOfs;
	void* lpOptionalHitPtr;
	WORD lpSearchTermID;
	WORD nLength;
	WORD nCodePage;
	WORD nFlags;
};

LONG __stdcall XT_ProcessSearchHit(struct SearchHitInfo* info)
{
	//XWF_OutputMessage (L"X-Tension proc. sh", 0);
	return 0;
}

