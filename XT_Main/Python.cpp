///////////////////////////////////////////////////////////////////////////////
// X-Tension API - template for new X-Tensions
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "X-Tension.h"
#include "BGStringTemplates.h"
#include "BGCPString.h"

#include <Python.h>
#include <Psapi.h>

#include <iostream>

// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

// "Embedding Python in Your C Programs"
// http://www.linuxjournal.com/article/8497?page=0,1

// "Extending and Embedding the Python Interpreter"
// http://docs.python.org/release/2.5.2/ext/ext.html

//const char* PythonScriptPath = "D:\\devel\\XT_C_Samples\\src\\Sample.py";
//const char* PythonScriptPath = "Sample";

#define FILE_NUMBER FILE_NO_PYTHON_CPP

///////////////////////////////////////////////////////////////////////////////
// Global variables

wchar_t* PythonScriptPaths;
const wchar_t* currScript;

///////////////////////////////////////////////////////////////////////////////

void XWF_OutputMessageStr(const BGCPString& str, DWORD nFlags = 0)
{
	BGCPString strCopy = str;
	strCopy.convertToCP(CP_UTF16_LE);
	XWF_OutputMessage(strCopy.getPtr<wchar_t>(), nFlags);
}

///////////////////////////////////////////////////////////////////////////////
// Call all scripts in config with given prefix and postfix
// Returns the number of successfully executed scripts

int callScripts(const BGCPString& prefix, const BGCPString& postfix, bool changeDirs = false)
{
	int success = 0;
	if (PythonScriptPaths == NULL) {
		// Nothing to do -> Optimistic view: Everything done immediately...
		return 0;
	}

	SET_SCOPE;
	const PathChar* cfgLine = PythonScriptPaths;
	PathChar oldDir[MAX_PATH];
	if (GetCurrentDirectoryW(MAX_PATH, oldDir) == 0) {
		oldDir[0] = 0;
	}

	// Retrieve paths and script names from the configuration, assuming that
	// each line contains a path, a script name, or both
	while (cfgLine[0] != 0) {
		BGCPString dir(cfgLine, CP_SYSTEM);
		BGCPString script;
		size_t len = wcslen(cfgLine);

		if (dir.endsWith(".py")) {
			size_t lastPathDelimiter = 0;
			if (bgstrrscan(cfgLine, L'\\', len, 0, lastPathDelimiter)) {
				dir.setByteCount(sizeof(PathChar) * lastPathDelimiter);
				script = BGCPString(cfgLine + lastPathDelimiter + 1, CP_SYSTEM);
				currScript = cfgLine + lastPathDelimiter + 1;
			} else {
				dir.clear();
				currScript = cfgLine;
				script = cfgLine;
			}
		}

		// Import module must be in the same directory as XT_Python
		if (!dir.empty() && changeDirs) {
			if (!SetCurrentDirectory(dir.getAsPath())) {
				BGCPString::getOSError().printLn();
			}
		}

		if (script.endsWith(".py")) {
			script.reduceBy(".py");
		}

		// Execute script?
		if (!script.empty()) {
			BGCPString cmd = prefix + script + postfix;
			cmd.convertToCP(CP_ASCII);
			if (PyRun_SimpleString(cmd.getPtr<char>()) == -1) {
				XWF_OutputMessageStr(BGCPString("Failed to execute: ") + cmd);
			} else {
				++success;
			}
		}
		cfgLine += len + 1;
	}

	if (changeDirs) {
		SetCurrentDirectory(oldDir);
	}
	currScript = NULL;
	RETURN success;
}

///////////////////////////////////////////////////////////////////////////////

BGCPString getUnicodeFromPythonObject(PyObject* po, size_t& len)
{
	BGCPString result;

	if (PyUnicode_Check(po)) {
		// Retrieve Unicode string and print it
		len = PyUnicode_GET_LENGTH(po) + 1;
		result.resizeBuffer(sizeof(wchar_t) * (len+1));
		PyUnicode_AsWideChar((PyObject*)po, result.getPtr<wchar_t>(), len);
		auto newLen = bgstrlen<wchar_t>(result.getPtr<wchar_t>());
		result.updateData(CP_UTF16_LE, sizeof(wchar_t) * newLen);
	} else {
		// No Unicode ... try to get ANSI string and convert
		//const char* astring = PyString_AsString(po);

		PyObject* temp_bytes = PyUnicode_AsEncodedString(po, "UTF-8", "strict"); // Owned reference
		if (temp_bytes != NULL) {
			const char* astring = PyBytes_AS_STRING(temp_bytes); // Borrowed pointer
			result = BGCPString(astring, CP_UTF8);
			Py_DecRef(temp_bytes);
		} else {
			// TODO: Handle encoding error.
		}
	}

	return result;
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_OutputMessage_Wrapper(PyObject *self, PyObject *args)
{
	// Parse arguments
	long int flags;
	PyObject* po1 = NULL;
	PyObject* po2 = NULL;

	if (!PyArg_UnpackTuple(args, "XWF_OutputMessage_Wrapper", 2, 2, &po1, &po2)) {
		return NULL;
	}
	if (po1 == NULL || po2 == NULL) {
		return NULL;
	}
	flags = PyLong_AsLong(po2);
	size_t len = 0;
	BGCPString str = getUnicodeFromPythonObject(po1, len);

	// Filter out empty lines
	if (str != BGCPString::EOL) {
		len *= sizeof(wchar_t);
		BGCPString msg = BGCPString(currScript, CP_SYSTEM)  + ": " + str;
		XWF_OutputMessageStr(msg, flags);
	}

	return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetVolumeName_Wrapper(PyObject *self, PyObject *args)
{
	DWORD nameType;
	Py_ssize_t volume;
	if (!PyArg_ParseTuple(args, "nl", &volume, &nameType)) {
		return NULL;
	}

	wchar_t buf[256];
	buf[0] = 0;
	XWF_GetVolumeName((HANDLE)volume, buf, nameType);
	size_t len = wcslen(buf);

	return PyUnicode_FromWideChar(buf, len);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetVolumeFileSystem_Wrapper(PyObject *self, PyObject *args)
{
	Py_ssize_t volume;
	if (!PyArg_ParseTuple(args, "n", &volume)) {
		return NULL;
	}

	long fsType;
	XWF_GetVolumeInformation((HANDLE)volume, &fsType, NULL, NULL, NULL, NULL);

	return PyLong_FromLong(fsType);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetVolumeBytesPerSector_Wrapper(PyObject *self, 
   PyObject *args)
{
	Py_ssize_t volume;
	if (!PyArg_ParseTuple(args, "n", &volume)) {
		return NULL;
	}

	DWORD bytesPerSector;
	LONG fileSystem = 0;
	DWORD sectorsPerCluster = 0;
	int64_t clusterCount = 0;
	int64_t lpFirstClusterSectorNo = 0;
	XWF_GetVolumeInformation((HANDLE)volume, &fileSystem, &bytesPerSector, &sectorsPerCluster,
		&clusterCount, &lpFirstClusterSectorNo);

	return PyLong_FromLong(bytesPerSector);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetVolumeSectorsPerCluster_Wrapper(PyObject *self, 
   PyObject *args)
{
	Py_ssize_t volume = 0;
	if (!PyArg_ParseTuple(args, "n", &volume)) {
		return NULL;
	}

	DWORD SectorsPerCluster;
	XWF_GetVolumeInformation((HANDLE)volume, NULL, NULL, &SectorsPerCluster,
		NULL, NULL);

	return PyLong_FromLong(SectorsPerCluster);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetVolumeClusterCount_Wrapper(PyObject *self, 
   PyObject *args)
{
	Py_ssize_t volume;
	if (!PyArg_ParseTuple(args, "n", &volume)) {
		return NULL;
	}

	INT64 ClusterCount = 0;
	XWF_GetVolumeInformation((HANDLE)volume, NULL, NULL, NULL,
		&ClusterCount, NULL);

	return PyLong_FromLongLong(ClusterCount);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetVolumeFirstClusterSectorNo_Wrapper(PyObject *self, 
   PyObject *args)
{
	Py_ssize_t volume;
	if (!PyArg_ParseTuple(args, "n", &volume)) {
		return NULL;
	}

	long long int FirstClusterSectorNo = 0;
	XWF_GetVolumeInformation((HANDLE)volume, NULL, NULL, NULL, NULL,
		&FirstClusterSectorNo);

	return PyLong_FromLongLong(FirstClusterSectorNo);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetSectorContentsString_Wrapper(PyObject *self, 
   PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_GetSectorContentsString_Wrapper", 2, 2, &po1, &po2)) {
      return NULL;
   }
   Py_ssize_t volume = PyLong_AsLongLong(po1);
   INT64 sector = PyLong_AsLongLong(po2);

   wchar_t buf[256];
   buf[0] = 0;
   XWF_GetSectorContents((HANDLE) volume, sector, buf, NULL);
   size_t len = wcslen(buf);

   return PyUnicode_FromWideChar(buf, len);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetItemIDForSector_Wrapper(PyObject *self, 
   PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;

   if (!PyArg_UnpackTuple(args, "XWF_GetItemIDForSector_Wrapper", 2, 2, &po1, &po2))
      return NULL;
   Py_ssize_t volume = PyLong_AsLongLong(po1);
   INT64 sector = PyLong_AsLongLong(po2);

   long itemID;
   XWF_GetSectorContents((HANDLE) volume, sector, NULL, &itemID);

   return PyLong_FromLong(itemID);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_Read_Wrapper(PyObject *self, PyObject *args)
{
   INT64 offset;
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   PyObject* po3 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_Read_Wrapper", 3, 3, &po1, &po2, &po3))
      return NULL;
   Py_ssize_t volume = PyLong_AsLongLong(po1);
   offset = PyLong_AsLongLong(po2);
   long int toRead = PyLong_AsLong(po3);

   PyObject* pyArray = PyByteArray_FromStringAndSize(NULL, 0);
   int result = PyByteArray_Resize(pyArray, toRead);
   if (result < 0) // -1: error, 0: ok
      return NULL;
   XWF_Read((HANDLE) volume, offset, (BYTE*)PyByteArray_AsString(pyArray), toRead);

   return pyArray;
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetItemCount_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_GetItemCount_Wrapper", 1, 1, &po1)) {
      return NULL;
   }
   Py_ssize_t volume = PyLong_AsLongLong(po1);

   if (volume < 0) // -1: error, 0: ok
      return NULL;
   DWORD count = XWF_GetItemCount((HANDLE) volume);

   return PyLong_FromLong(count);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetItemSize_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_GetItemSize_Wrapper", 1, 1, &po1))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) // -1: error, 0: ok
      return NULL;
   //LARGE_INTEGER size;
   //size = XWF_GetItemSize(itemID);

   //return PyLong_FromLongLong(size.QuadPart);

   INT64 size = XWF_GetItemSize(itemID);

   return PyLong_FromLongLong(size);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * getFileSystemInfoOffset_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_GetItemOfs_Wrapper", 1, 1, &po1))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) // -1: error, 0: ok
      return NULL;
   INT64 offset, dummy;
   XWF_GetItemOfs(itemID, &offset, &dummy);

   return PyLong_FromLongLong(offset);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * getItemFirstDataSector_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "getItemFirstDataSector_Wrapper", 1, 1, &po1))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) // -1: error, 0: ok
      return NULL;
   INT64 sector, dummy;
   XWF_GetItemOfs(itemID, &dummy, &sector);

   return PyLong_FromLongLong(sector);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * GetItemName_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "GetItemName_Wrapper", 1, 1, &po1))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) // -1: error, 0: ok
      return NULL;
   const wchar_t* name = XWF_GetItemName(itemID);

   // Compute size using wcslen, later versions of Python may accept passing 
   // -1 here, but this is the downward compatible way of doing it
   size_t len = wcslen(name);
   return PyUnicode_FromWideChar(name, len); 
}

///////////////////////////////////////////////////////////////////////////////

PyObject* XWF_GetItemInformation_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   if (!PyArg_UnpackTuple(args, "GetItemInformation_Wrapper", 2, 2, &po1, &po2))
      return NULL;
   long int itemID = PyLong_AsLong(po1);
   long int infoType = PyLong_AsLong(po2);
   BOOL success = true;

   INT64 result = 
      XWF_GetItemInformation(itemID, infoType, &success);

   PyObject* o1 = PyLong_FromLongLong(result);
   PyObject* o2 = PyBool_FromLong(success);
   PyObject* tuple = PyTuple_Pack(2, o1, o2);

   Py_DecRef(o1);
   Py_DecRef(o2);
   return tuple;
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetItemParent_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "GetItemParent_Wrapper", 1, 1, &po1))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) // -1: error, 0: ok
      return NULL;

   LONG pid = XWF_GetItemParent(itemID);
   return PyLong_FromLong(pid); 
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetReportTableAssocs_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_GetReportTableAssocsCount_Wrapper", 1, 1, &po1))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) // -1: error, 0: ok
      return NULL;

   const int bufLen = 2048;
   wchar_t buf[bufLen];
   buf[0] = 0;
   LONG count = XWF_GetReportTableAssocs(itemID, buf, bufLen);
   size_t bufUsed = wcslen(buf);
   return PyUnicode_FromWideChar(buf, bufUsed); 
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_AddToReportTable_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   PyObject* po3 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_AddToReportTable_Wrapper", 2, 3, &po1, &po2, &po3))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) // -1: error, 0: ok
      return NULL;

   size_t len = 0;
   BGCPString assocName = getUnicodeFromPythonObject(po2, len);

   DWORD flags = 0;
   if (po3 != NULL) {
      if (PyLong_Check(po3)) {
         flags = PyLong_AsLong(po3);
      }
   }

   assocName.convertToCP(CP_UTF16_LE);
   LONG result = XWF_AddToReportTable(itemID, assocName.getPtr<wchar_t>(), flags);
   return PyLong_FromLong(result);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_GetComment_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_GetComment_Wrapper", 1, 1, &po1))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) // -1: error, 0: ok
      return NULL;

   wchar_t * buf = XWF_GetComment(itemID);

   if (buf == NULL)
      buf = L"";

   size_t bufUsed = wcslen(buf);
   return PyUnicode_FromWideChar(buf, bufUsed); 
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_AddComment_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   PyObject* po3 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_AddComment_Wrapper", 2, 3, &po1, &po2, &po3))
      return NULL;
   long int itemID = PyLong_AsLong(po1);

   if (itemID < 0) {
       // -1: error, 0: ok
      return NULL;
   }

   size_t len = 0;
   BGCPString comment = getUnicodeFromPythonObject(po2, len);

   DWORD howToAdd = 0;
   if (po3 != NULL) {
      if (PyLong_Check(po3)) {
         howToAdd = PyLong_AsLong(po3);
      }
   }

   comment.convertToCP(CP_UTF16_LE);
   BOOL result = XWF_AddComment(itemID, comment.getPtr<wchar_t>(), howToAdd);
   return PyBool_FromLong(result); 
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_ShowProgress_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_GetComment_Wrapper", 1, 2, &po1, &po2))
      return NULL;

   size_t len = 0;
   BGCPString caption = getUnicodeFromPythonObject(po1, len);

   DWORD flags = 0;
   if (po2 != NULL) {
      flags = PyLong_AsLong(po2);
   }

   caption.convertToCP(CP_UTF16_LE);
   XWF_ShowProgress(caption.getPtr<wchar_t>(), flags);
   return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_ProcessMessages(PyObject *self, PyObject *args)
{
   MSG mss;
   if (PeekMessageW(&mss,0,0,0,PM_REMOVE)) {
      TranslateMessage(&mss);
      DispatchMessage(&mss);
   }
   return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_SetProgressPercentage_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_SetProgressPercentage_Wrapper", 1, 1, &po1))
      return NULL;

   DWORD percent = 0;
   if (po1 != NULL) {
      percent = PyLong_AsLong(po1);
   }

   XWF_SetProgressPercentage(percent);
   XWF_ProcessMessages(NULL, NULL);
   return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_SetProgressDescription_Wrapper(PyObject *self, PyObject *args)
{
	PyObject* po1 = NULL;
	if (!PyArg_UnpackTuple(args, "XWF_SetProgressDescription_Wrapper", 1, 1, &po1)) {
		return NULL;
	}

	size_t len = 0;
	BGCPString caption = getUnicodeFromPythonObject(po1, len);

	caption.convertToCP(CP_UTF16_LE);
	XWF_SetProgressDescription(caption.getPtr<wchar_t>());
	return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_HideProgress_Wrapper(PyObject *self, PyObject *args)
{
   XWF_HideProgress();
   XWF_ProcessMessages(NULL, NULL);
   //XWF_OutputMessage(L"XWF_HideProgress_Wrapper called\n", 0);
   return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_CreateItem_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_CreateItem_Wrapper", 1, 2, &po1, &po2))
      return NULL;

   size_t len = 0;
   BGCPString fn = getUnicodeFromPythonObject(po1, len);
   DWORD flags = 0;

   if (po2 != NULL) {
      flags = PyLong_AsLong(po2);
   }

   fn.convertToCP(CP_UTF16_LE);
   LONG result = XWF_CreateItem(fn.getPtr<wchar_t>(), flags);
   return PyLong_FromLong(result);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_SetItemParent_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_SetProgressDescription_Wrapper", 2, 2, &po1, &po2))
      return NULL;

   LONG child = 0;
   LONG parent = 0;

   if (po1 != NULL) {
      child = PyLong_AsLong(po1);
   }

   if (po2 != NULL) {
      parent = PyLong_AsLong(po2);
   }

   XWF_SetItemParent(child, parent);
   return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_SetItemOfs_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   PyObject* po3 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_SetItemOfs_Wrapper", 3, 3, &po1, &po2, &po3))
      return NULL;

   LONG nItemID = 0;

   INT64 nDefOffs = 0;
   INT64 startSector = 0;

   if (po1 != NULL) {
      nItemID = PyLong_AsLong(po1);
   }

   if (po2 != NULL) {
      nDefOffs = PyLong_AsLongLong(po2);
   }

   if (po3 != NULL) {
      startSector = PyLong_AsLongLong(po3);
   }

   XWF_SetItemOfs(nItemID, nDefOffs, startSector);
   return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * XWF_SetItemSize_Wrapper(PyObject *self, PyObject *args)
{
   PyObject* po1 = NULL;
   PyObject* po2 = NULL;
   if (!PyArg_UnpackTuple(args, "XWF_SetItemSize_Wrapper", 2, 2, &po1, &po2))
      return NULL;

   LONG nItemID = 0;

   if (po1 != NULL) {
      nItemID = PyLong_AsLong(po1);
   }

   INT64 size = 0;
   if (po2 != NULL) {
      size = PyLong_AsLongLong(po2);
   } else
      size = 0;

   XWF_SetItemSize(nItemID, size);
   return PyLong_FromLong(0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * GetOpenFileName_Wrapper(PyObject *self, PyObject *args)
{
   OPENFILENAME info;
   wchar_t fnBuf[MAX_PATH+1];

   memset(&info, 0, sizeof(info));
   info.lStructSize = sizeof(info);
   info.lpstrFile = fnBuf;
   info.nMaxFile = MAX_PATH;
   info.lpstrTitle = L"Please select a file to open";
   fnBuf[0] = 0;

   if (GetOpenFileName(&info) > 0) {
      // User selected a file and clicked OK
      size_t len = wcslen(info.lpstrFile);
      return PyUnicode_FromWideChar(fnBuf, len); 
   } else {
      // User abort
      return PyUnicode_FromWideChar(NULL, 0); 
   }
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * GetSaveFileName_Wrapper(PyObject *self, PyObject *args)
{
   OPENFILENAME info;
   wchar_t fnBuf[MAX_PATH+1];

   memset(&info, 0, sizeof(info));
   info.lStructSize = sizeof(info);
   info.lpstrTitle = L"Please select a file to save";
   info.lpstrFile = fnBuf;
   info.nMaxFile = MAX_PATH;
   fnBuf[0] = 0;

   if (GetSaveFileName(&info) > 0) {
      // User selected a file and clicked OK
      size_t len = wcslen(info.lpstrFile);
      return PyUnicode_FromWideChar(fnBuf, len); 
   } else {
      // User abort
      DWORD error = GetLastError();
      return PyUnicode_FromWideChar(NULL, 0);
   }
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * AllocConsole_Wrapper(PyObject *self, PyObject *args)
{
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	//PyRun_SimpleString("sys.open('CONOUT$', 'wt')");
	std::cout << "Hello console" << std::endl;
	return PyUnicode_FromWideChar(NULL, 0);
}

///////////////////////////////////////////////////////////////////////////////

static PyObject * GetExtractedMetadata_Wrapper(PyObject *self, PyObject *args)
{
	PyObject* po1 = NULL;
	if (!PyArg_UnpackTuple(args, "GetExtractedMetadata_Wrapper", 1, 1, &po1))
		return NULL;
	long int itemID = PyLong_AsLong(po1);

	if (itemID < 0) // -1: error, 0: ok
		return NULL;
	const wchar_t* name = XWF_GetExtractedMetadata(itemID);

	// Compute size using wcslen, later versions of Python may accept passing 
	// -1 here, but this is the downward compatible way of doing it
	size_t len = bgstrlen(name);
	return PyUnicode_FromWideChar(name, len); 
}

///////////////////////////////////////////////////////////////////////////////
// XT_Init

// This list is the heart of accessing XWF features from Python - it defines
// the list of callable functions
static PyMethodDef XT_Methods[] = {
	{"OutputMessage",  XWF_OutputMessage_Wrapper, METH_VARARGS, 
		"OutputMessage(msg, flags): Print msg to message window"},
	{"GetVolumeName",  XWF_GetVolumeName_Wrapper, METH_VARARGS, 
		"GetVolumeName(hVolume, nameType): Returns name of volume as a string"},
	{"GetVolumeFileSystem",  XWF_GetVolumeFileSystem_Wrapper, METH_VARARGS, 
		"GetVolumeFileSystem(hVolume): Returns file system used by volume"},
	{"GetVolumeBytesPerSector",  XWF_GetVolumeBytesPerSector_Wrapper, METH_VARARGS, 
		"GetVolumeBytesPerSector(hVolume): Returns bytes per sector used by volume"},
	{"GetVolumeSectorsPerCluster",  XWF_GetVolumeSectorsPerCluster_Wrapper, METH_VARARGS, 
		"GetVolumeSectorsPerCluster(hVolume): Returns sectors per cluster used by volume"},
	{"GetVolumeClusterCount",  XWF_GetVolumeClusterCount_Wrapper, METH_VARARGS, 
		"GetVolumeClusterCount(hVolume): Return numbers of cluster used by volume"},
	{"GetVolumeFirstClusterSectorNo",  XWF_GetVolumeFirstClusterSectorNo_Wrapper, METH_VARARGS, 
		"GetVolumeFirstClusterSectorNo(hVolume): Returns sector number of the "
		"first cluster used by volume"},
	{"GetSectorContentsString",  XWF_GetSectorContentsString_Wrapper, METH_VARARGS, 
		"GetSectorContentsString(hVolume, sector): Returns description for sector contents"},
	{"GetItemIDForSector",  XWF_GetItemIDForSector_Wrapper, METH_VARARGS, 
		"GetItemIDForSector(hVolume, sector): Returns itemID for file that sector belongs to"},
	{"Read",  XWF_Read_Wrapper, METH_VARARGS, 
		"Read(hVolume, sector, byteCount): Returns bytearray read from offset in volume"},
	{"GetItemCount",  XWF_GetItemCount_Wrapper, METH_VARARGS, 
		"GetItemCount(hVolume): Returns the number of items in the current volume snapshot "
		"of the given volume"},
	{"GetItemSize",  XWF_GetItemSize_Wrapper, METH_VARARGS, 
		"GetItemSize(itemID): Returns the size of the given item"},
	{"GetFileSystemInfoOffset",  getFileSystemInfoOffset_Wrapper, METH_VARARGS, 
		"GetFileSystemInfoOffset(itemID): Returns the offset to the file system data "
		"of the given item in its volume"},
	{"GetItemFirstDataSector",  getItemFirstDataSector_Wrapper, METH_VARARGS, 
		"GetItemFirstDataSector(itemID): Returns the sector where file data starts"},
	{"GetItemName",  GetItemName_Wrapper, METH_VARARGS, 
		"GetItemName(itemID): Returns a string containing the file name"},
	{"GetItemInformation", XWF_GetItemInformation_Wrapper, METH_VARARGS, 
		"GetItemInformation(itemID, infoType): Returns a tuple - the requested "
		"data, and whether the information was retrieved successfully"},
	{"GetItemParent", XWF_GetItemParent_Wrapper, METH_VARARGS, 
		"GetItemParent(itemID): Returns the ID of the item's parent"},
	{"GetReportTableAssocs", XWF_GetReportTableAssocs_Wrapper, METH_VARARGS, 
		"GetReportTableAssocs(itemID): Returns the report table association strings for "
		"itemID as a comma-separated list"},
	{"AddToReportTable", XWF_AddToReportTable_Wrapper, METH_VARARGS, 
		"AddToReportTable(itemID, ReportTableName, flags): Add a report table association for itemID."
		"The flags are optional, please see the X-Tension API webpage for a list of flags."},
	{"GetComment", XWF_GetComment_Wrapper, METH_VARARGS, 
		"GetComment(itemID): Returns the comment for itemID"},
	{"AddComment", XWF_AddComment_Wrapper, METH_VARARGS, 
		"AddComment(itemID, comment, howToAdd): Adds or appends a comment for a file."
		"Please see the X-Tension API webpage for a list of values for howToAdd (default: replace)"},
	{"ShowProgress", XWF_ShowProgress_Wrapper, METH_VARARGS, 
		"ShowProgress(comment, flags): Show a progress window, flags are optional (see API webpage for a list)"},
	{"SetProgressPercentage", XWF_SetProgressPercentage_Wrapper, METH_VARARGS, 
		"SetProgressPercentage(percent): Set the progress in percent"},
	{"SetProgressDescription", XWF_SetProgressDescription_Wrapper, METH_VARARGS, 
		"SetProgressDescription(percent): Set descriptive text for the progress window"},
	{"HideProgress", XWF_HideProgress_Wrapper, METH_VARARGS, 
		"HideProgress(): Hide progress window"},
	{"CreateItem", XWF_CreateItem_Wrapper, METH_VARARGS, 
		"CreateItem(FileName, flags): Creates a new item (file or directory) in the volume snapshot"},
	{"SetItemSize", XWF_SetItemSize_Wrapper, METH_VARARGS, 
		"SetItemSize(nItemID, size): Sets the size of the item in bytes. -1 means unknown size. "},
	{"SetItemParent", XWF_SetItemParent_Wrapper, METH_VARARGS, 
		"SetItemParent(nItemID, nParentID): Sets the parent of the specified child item"},
	{"SetItemOfs", XWF_SetItemOfs_Wrapper, METH_VARARGS, 
		"SetItemOfs(nItemID, offset, startSector): Sets the offset and sector number for an item."},
	{"ProcessMessages", XWF_ProcessMessages, METH_VARARGS, 
		"ProcessMessages(): Process internal application messages, to keep the application responsive to user input"},
	{"GetOpenFileName", GetOpenFileName_Wrapper, METH_VARARGS, 
		"GetOpenFileName(): Displays a file open dialog and returns the name of the selected file"},
	{"GetSaveFileName", GetSaveFileName_Wrapper, METH_VARARGS, 
		"GetSaveFileName(): Displays a file save dialog and returns the name of the selected file"},
	{"AllocConsole", AllocConsole_Wrapper, METH_VARARGS, 
	"AllocConsole(): Open a console window for printing messages"},
	{"GetExtractedMetadata", GetExtractedMetadata_Wrapper, METH_VARARGS, 
	"GetExtractedMetadata(itemID): Returns a string containing the extracted metadata"},

	{NULL, NULL, 0, NULL}        /* End of list */
};

#define XWF_MODULE_NAME "xwf"

static struct PyModuleDef moduleDef =
{
    PyModuleDef_HEAD_INIT,
    XWF_MODULE_NAME, // name of module 
    "Module to integrate Python with X-Ways Forensics", // module documentation, may be NULL
    -1,          // size of per-interpreter state of the module, or -1 if the module keeps 
                 // state in global variables.
    XT_Methods,
    NULL,
    NULL,
    NULL,
    NULL
};

static PyObject*
PyInit_xwf(void)
{
    return PyModule_Create(&moduleDef);
}

LONG __stdcall XT_Init(CallerInfo info, DWORD nFlags, HANDLE hMainWnd, void* lpReserved)
{
	PythonScriptPaths = NULL;
	currScript = NULL;

	// Useful to attach the debugger ...
	//MessageBox(0, L"world", L"Hello", 0);

	if (XT_RetrieveFunctionPointers() > 0) {
		XWF_OutputMessage(L"Failed to obtain function pointers\n", 0);
		return -1; // abort
	}

	auto imported = PyImport_AppendInittab(XWF_MODULE_NAME, &PyInit_xwf);
	if (imported == -1) {
		XWF_OutputMessage(L"Failed to add xwf import to Python\n", 0);
		//return -2; // abort
	}

	Py_Initialize();
	if (Py_IsInitialized() == 0) {
		XWF_OutputMessage(L"Failed to initialize Python\n", 0);
		return -2; // abort
	}

	// Open Python configuration - script list
	wchar_t cfgPath[MAX_PATH];
	HANDLE procH = GetCurrentProcess();
	GetModuleFileNameEx(procH, 0, cfgPath, MAX_PATH);
	size_t backSlashPos = 0;
	if (bgstrrscan(cfgPath, L'\\', wcslen(cfgPath), 0, backSlashPos)) {
		cfgPath[backSlashPos] = 0;
		bgstrcat((wchar_t*)cfgPath, (wchar_t*)L"\\Python.cfg", MAX_PATH);
		HANDLE h =
			CreateFile(cfgPath, GENERIC_READ, FILE_SHARE_READ, NULL,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h != INVALID_HANDLE_VALUE) {
			DWORD FileSize = GetFileSize(h, NULL);
			PythonScriptPaths = (wchar_t*)(new char[FileSize]);
			DWORD read = 0;
			ReadFile(h, PythonScriptPaths, FileSize, &read, NULL);
			if (read != FileSize) {
				safeDelete(PythonScriptPaths);
			}
			CloseHandle(h);
		}
	}

	if (PythonScriptPaths != nullptr) {
		callScripts("import ", "", true);
		BGCPString postfix = ".XT_Init(";
		postfix += BGCPString::fromInt(info.version);
		postfix += ", ";
		postfix += BGCPString::fromInt(nFlags);
		postfix += ", ";
		postfix += BGCPString::fromInt((UINT_PTR)(hMainWnd));
		postfix += ", ";
		postfix += BGCPString::fromInt((UINT_PTR)(lpReserved));
		postfix += ")";
		callScripts("", postfix);
	}

	return 1; // not thread-safe, since the global state is stored in a few global variables ...
}

///////////////////////////////////////////////////////////////////////////////
// XT_Done

LONG __stdcall XT_Done(void* lpReserved)
{
	BGCPString exp = ".XT_Done(";
	exp += BGCPString::fromInt((UINT_PTR)(lpReserved));
	exp += ")";
	callScripts("", exp);
	Py_Finalize();

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_About

LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved)
{
	// Useful to attach the debugger ...
	//MessageBox(0, L"world", L"Hello", 0);

	OPENFILENAME lpofn;
	const int FN_LIMIT = 32 * 1024;
	memset(&lpofn, 0, sizeof(OPENFILENAME));
	lpofn.lStructSize = sizeof(OPENFILENAME);
	lpofn.hwndOwner = (HWND)hParentWnd;
	lpofn.lpstrFilter = L"Python Scripts\0*.py\0All Files\0*\0\0";
	lpofn.lpstrFile = new wchar_t[FN_LIMIT];
	lpofn.lpstrFile[0] = 0;
	lpofn.nMaxFile = FN_LIMIT;
	lpofn.lpstrTitle = L"Please select the Python script(s) you want to execute";
	lpofn.Flags = OFN_ALLOWMULTISELECT | OFN_EXPLORER; // leads to old-style dialog .. really ugly!
	//lpofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR; // ignored?

	wchar_t exeFN[MAX_PATH];
	HANDLE procH = GetCurrentProcess();
	GetModuleFileNameEx(procH, 0, exeFN, MAX_PATH);
	size_t backSlashPos = 0;
	if (bgstrrscan(exeFN, L'\\', wcslen(exeFN), 0, backSlashPos))
		exeFN[backSlashPos] = 0;
	lpofn.lpstrInitialDir = exeFN;

	if (GetOpenFileName(&lpofn)) {
		// Store the results as new configuration
		BGCPString cfgPath(exeFN, CP_SYSTEM);
		cfgPath.addPathSep("Python.cfg");
		HANDLE h =
			CreateFile(cfgPath.getAsPath(), GENERIC_WRITE, FILE_SHARE_READ, NULL,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		wchar_t* iter = lpofn.lpstrFile;
		while (iter[0] != 0) {
			iter += wcslen(iter) + 1;
		}
		DWORD written;
		DWORD cfgSize = (DWORD)(2 * (iter - lpofn.lpstrFile) + 2);
		WriteFile(h, lpofn.lpstrFile, cfgSize, &written, NULL);
		CloseHandle(h);

		// Use results as new configuration
		safeDelete(PythonScriptPaths);
		PythonScriptPaths = new wchar_t[cfgSize];
		memcpy(PythonScriptPaths, lpofn.lpstrFile, cfgSize);
	}
	delete lpofn.lpstrFile;

	XWF_OutputMessage(L"XT_Python built on " __DATE__ "\n", 0);

    char pythonMainVersion = PY_MAJOR_VERSION;
    char pythonMinorVersion = PY_MINOR_VERSION;
    char pythonMicroVersion = PY_MICRO_VERSION;
    BGCPString msg = BGCPString("Linked to Python ") + BGCPString::fromInt(PY_MAJOR_VERSION) + BGCPString(".") + 
        BGCPString::fromInt(PY_MINOR_VERSION) + BGCPString(".") + 
        BGCPString::fromInt(PY_MICRO_VERSION) + BGCPString(".") + 
        BGCPString(", copyright Python Software ", 0) + BGCPString::EOL;
    XWF_OutputMessageStr(msg, 0);
	XWF_OutputMessage(L"\n", 0);
	XWF_OutputMessage(L"Running \"About\" functions for selected Python scripts:\n", 0);

	callScripts("import ", "", true);

	BGCPString postfix = ".XT_About(";
	postfix += BGCPString::fromInt((UINT_PTR)(hParentWnd));
	postfix += ", ";
	postfix += BGCPString::fromInt((UINT_PTR)(lpReserved));
	postfix += ")";

	callScripts("", postfix);

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_Prepare

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, 
   void* lpReserved)
{
   BGCPString postfix = ".XT_Prepare(";
   postfix += BGCPString::fromInt((uintptr_t)(hVolume));
   postfix += ", ";
   postfix += BGCPString::fromInt((uintptr_t)(hEvidence));
   postfix += ", ";
   postfix += BGCPString::fromInt(nOpType);
   postfix += ", ";
   postfix += BGCPString::fromInt((UINT_PTR)(lpReserved));
   postfix += ")";
   callScripts("", postfix);

   return 1; // Call XT_ProcessItem or XT_ProcessItemEx
}

///////////////////////////////////////////////////////////////////////////////
// XT_Finalize

LONG __stdcall XT_Finalize(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, 
   void* lpReserved)
{
   BGCPString postfix = ".XT_Finalize(";
   postfix += BGCPString::fromInt((UINT_PTR)(hVolume));
   postfix += ", ";
   postfix += BGCPString::fromInt((UINT_PTR)(hEvidence));
   postfix += ", ";
   postfix += BGCPString::fromInt(nOpType);
   postfix += ", ";
   postfix += BGCPString::fromInt((UINT_PTR)(lpReserved));
   postfix += ")";
   callScripts("", postfix);

   return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItem

LONG __stdcall XT_ProcessItem(LONG nItemID, void* lpReserved)
{
   BGCPString postfix = ".XT_ProcessItem(";
   postfix += BGCPString::fromInt(nItemID);
   postfix += ", ";
   postfix += BGCPString::fromInt((UINT_PTR)(lpReserved));
   postfix += ")";
   callScripts("", postfix);

   return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessItemEx

LONG __stdcall XT_ProcessItemEx(LONG nItemID, HANDLE hItem, void* lpReserved)
{
   BGCPString postfix = ".XT_ProcessItemEx(";
   postfix += BGCPString::fromInt(nItemID);
   postfix += ", ";
   postfix += BGCPString::fromInt((UINT_PTR)hItem);
   postfix += ", ";
   postfix += BGCPString::fromInt((UINT_PTR)(lpReserved));
   postfix += ")";
   callScripts("", postfix);

   return 0;
}

///////////////////////////////////////////////////////////////////////////////
// XT_ProcessSearchHit

#pragma pack(push)
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
#pragma pack(pop)

LONG __stdcall XT_ProcessSearchHit(struct SearchHitInfo* info)
{
   BGCPString postfix = ".XT_ProcessSearchHit(";
   postfix += BGCPString::fromInt(info->iSize);
   postfix += ", ";
   postfix += BGCPString::fromInt(info->nItemID);
   postfix += ", ";
   postfix += BGCPString::fromInt(info->nRelOfs.QuadPart);
   postfix += ", ";
   postfix += BGCPString::fromInt(info->nAbsOfs.QuadPart);
   postfix += ", '";

   // Need to filter out certain characters from lpOptionalHitPtr
   if (info->lpOptionalHitPtr != NULL) {
      char* p = (char*) (info->lpOptionalHitPtr);
      WORD len = info->nLength;
      while (len > 0) {
         if (*p >= 32) {
            if (*p != '\'') {
               postfix.add<char>(p);
            }
            ++p;
            --len;
         } else
            len = 0;
      }
   }

   postfix += "', ";
   postfix += BGCPString::fromInt(info->lpSearchTermID);
   postfix += ", ";
   postfix += BGCPString::fromInt(info->nLength);
   postfix += ", ";
   postfix += BGCPString::fromInt(info->nCodePage);
   postfix += ", ";
   postfix += BGCPString::fromInt(info->nFlags);
   postfix += ")";
   postfix.convertToCP(CP_ASCII);
   callScripts("", postfix.getPtr<char>());

   return 0;
}

