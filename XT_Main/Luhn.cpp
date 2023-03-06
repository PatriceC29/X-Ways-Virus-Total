///////////////////////////////////////////////////////////////////////////////
// X-Tension API - Luhn sample implementation
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "X-Tension.h"
#include <math.h>

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

#include <vector>

//fptr_XWF_GetSize XWF_GetSize;

///////////////////////////////////////////////////////////////////////////////
// XT_Init

LONG __stdcall XT_Init(CallerInfo info, DWORD nFlags, HANDLE hMainWnd,
	void* lpReserved)
{
	XT_RetrieveFunctionPointers();
	//XWF_OutputMessage (L"X-Tension Init", 0);
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Done

LONG __stdcall XT_Done(void* lpReserved)
{
	//XWF_OutputMessage (L"X-Tension done", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About

LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved)
{
	XWF_OutputMessage(L"Luhn X-Tension - v1.0\n", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType,
	void* lpReserved)
{
	//XWF_OutputMessage (L"X-Tension prepare", 0);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Finalize

LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType,
	void* lpReserved)
{
	//XWF_OutputMessage (L"X-Tension finalize", 0);
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

const int minCCLen = 12;

bool Luhn(const wchar_t* ccnum, size_t len)
{
	if (len < minCCLen) {
		return false;
	}

	// cipher sum of doubled ciphers
	const int doubleCipherSums[] = { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };
	int sum = 0;
	int odd = (len & 1);
	const wchar_t* end = &(ccnum[len]);

	for (; ccnum < end; ++ccnum) {
		int digit = (*ccnum - '0');
		if (odd) {
			sum += digit;
			odd = 0;
		} else {
			sum += doubleCipherSums[digit];
			odd = 1;
		}
	}

	return (sum % 10 == 0);
}

// Remove all non-ciphers, return length of remaining string
size_t filter(wchar_t* buf, size_t len)
{
	size_t i = 0;
	size_t olen = 0;

	while (i < len) {
		wchar_t c = buf[i];
		if (c >= '0' && c <= '9') {
			buf[olen] = c;
			++olen;
		}
		++i;
	}

	return olen;
}

bool ccEntropyCheck(const wchar_t* ccnum, size_t len)
{
	// Count cipher frequency and probability
	std::vector<int> freq(10, 0); // init with 10 zeroes
	for (size_t i = 0; i < len; ++i) {
		int cipher = (ccnum[i] - '0');
		++freq[cipher];
	}

	// Compute entropy - not necessary, low entropy often caused by low number
	// of different ciphers, which can be checked faster
	/*double prob[10];
	for (size_t i = 0; i < 10; ++i)
	   prob[i] = ((double)freq[i]) / len;
	double entropy = 0;
	for (size_t i = 0; i < 10; ++i)
	   if (prob[i] > 0)
		  entropy -= prob[i] * log(prob[i]);*/

	// Count used ciphers
	int used = 0;
	for (size_t i = 0; i < 10; ++i)
		if (freq[i] > 0)
			++used;

	//if (used >= 3 || entropy > 1.0)
	if (used >= 3) {
		return true;
	} else {
		return false;
	}
}

LONG __stdcall XT_ProcessSearchHit(struct SearchHitInfo* info)
{
	//XWF_OutputMessage (L"X-Tension proc. sh", 0);
	if (info == NULL) {
		return 0;
	}
	if (info->iSize < 36) {
		return 0;
	}
	if (info->lpOptionalHitPtr == NULL) {
		return 0;
	}

	size_t wclen = 0;
	wchar_t ccnum[30];
	if (info->nCodePage != 1200) {
		wclen =
			MultiByteToWideChar(info->nCodePage, 0,
				(LPCSTR)info->lpOptionalHitPtr, info->nLength, ccnum, 25);
	} else {
		wclen = info->nLength / 2;
	}

	if (ccnum[0] == L'6' && ccnum[1] == L'2') {
		return 0; // China UnionPay, ok, no Luhn validation...
	}

	size_t TestLen = filter(ccnum, wclen);
	size_t removedChars = wclen - TestLen;
	ccnum[TestLen] = 0;

	if (Luhn(ccnum, TestLen)) {
		if (ccEntropyCheck(ccnum, TestLen)) {
			info->nLength = (WORD)(TestLen + removedChars);
			return 0; // ok
		}
	} else {
		--TestLen;
	}

	info->nFlags |= 0x0008; // ignore hit
	return 0;
}
