///////////////////////////////////////////////////////////////////////////////
// X-Tension API - template for new X-Tensions
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "Windows.h"
#include "X-Tension.h"
#include "string.h"
#include "wchar.h"
#include <stdlib.h>
#include <stdio.h>

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

DWORD gStartTime;

///////////////////////////////////////////////////////////////////////////////
// XT_Init

LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd,
   void* lpReserved)
{
   XT_RetrieveFunctionPointers();
   //XWF_OutputMessage (L"XT_Timer initialized", 0);
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Done

LONG __stdcall XT_Done(void* lpReserved)
{
   //XWF_OutputMessage (L"XT_Timer done", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About

LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved)
{
	XWF_OutputMessage (L"XT_Timer: Prints the duration of refine volume snapshot operations", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////

void appendDateTimeStr(wchar_t* msg, size_t bufLen)
{
	const int buf2Len = 100;
	wchar_t msg2[buf2Len];
	SYSTEMTIME sysTime;

	GetLocalTime(&sysTime);
	GetDateFormatEx(LOCALE_NAME_USER_DEFAULT, DATE_SHORTDATE, &sysTime, NULL,
		msg2, buf2Len, NULL);
	wcscat_s(msg, bufLen, msg2);
	wcscat_s(msg, bufLen, L", ");
	GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &sysTime, NULL, msg2, buf2Len);
	wcscat_s(msg, bufLen, msg2);
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, 
   void* lpReserved)
{
   //XWF_OutputMessage (L"X-Tension prepare", 0);
	wchar_t msg[100] = L"Refine volume snapshot started on ";
	appendDateTimeStr(msg, 100);
	XWF_OutputMessage(msg, 0);
	gStartTime = GetTickCount();
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Finalize

LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType,
	void* lpReserved)
{
	wchar_t msg[100] = L"Refine volume snapshot ended on ";
	appendDateTimeStr(msg, 100);
	wcscat(msg, L", ");

	DWORD stopTime = GetTickCount();
	DWORD delta = stopTime - gStartTime;

	if (delta > 100 * 1000) {
		DWORD seconds = (delta / 1000) % 60;
		DWORD minutes = (delta / (60 * 1000)) % 60;
		DWORD hours = (delta / (60 * 60 * 1000)) % 60;
		if (hours > 0) {
			wchar_t hbuf[10] = L"";
			_itow_s(hours, hbuf, 10, 10);
			wcscat_s(msg, hbuf);
			wcscat_s(msg, L" h ");
		}

		if (minutes > 0) {
			wchar_t mbuf[10] = L"";
			_itow_s(minutes, mbuf, 10, 10);
			wcscat_s(msg, mbuf);
			wcscat_s(msg, L" min ");
		}

		wchar_t sbuf[10] = L"";
		_itow_s(seconds, sbuf, 10, 10);
		wcscat_s(msg, sbuf);
		wcscat_s(msg, L" s ");
	} else {
		DWORD deciseconds = delta % 10;
		DWORD seconds = (delta / 1000) % 60;
		wchar_t sbuf[10], dsbuf[10];
		_itow_s(seconds, sbuf, 10, 10);
		_itow_s(deciseconds, dsbuf, 10, 10);
		wcscat_s(msg, sbuf);
		wcscat_s(msg, L".");
		wcscat_s(msg, dsbuf);
		wcscat_s(msg, L" s ");
	}

   XWF_OutputMessage (msg, 0);
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

