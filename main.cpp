#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <process.h>
#include <commctrl.h>
#include <stdio.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <tchar.h>
#include <memory>
#include <functional>
#pragma comment(lib,"Comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

HWND MainWindow = 0;
HINSTANCE hAppInstance = 0;

#include <WinBio.h>
#pragma comment(lib,"winbio.lib")



#include "fingerprintf.hpp"

// ----
#define DEFINE_GUID2(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
        EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }

// {339996B2-0A32-4ECE-A175-312629AF0000}
DEFINE_GUID2(GUID_DB_MY,
	0x339996b2, 0xa32, 0x4ece, 0xa1, 0x75, 0x31, 0x26, 0x29, 0xaf, 0x00, 0x00);

FINGERPRINTF fp;
int Unit = 0;
HRESULT hr = S_OK;
WINBIO_IDENTITY LastID = { 0 };
WINBIO_BIOMETRIC_SUBTYPE LastSub = 0;


// Helpers for GUI
BOOL RunAsAdmin(HWND hWnd, LPTSTR lpFile, LPTSTR lpParameters)
	{
	SHELLEXECUTEINFO sei = { 0 };
	sei.cbSize = sizeof(SHELLEXECUTEINFOW);
	sei.hwnd = hWnd;
	sei.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI;
	sei.lpVerb = _TEXT("runas");
	sei.lpFile = lpFile;
	sei.lpParameters = lpParameters;
	sei.nShow = SW_SHOWNORMAL;

	return ShellExecuteEx(&sei);
	}

void AddMessage(const wchar_t* t2)
	{
	HWND h = GetDlgItem(MainWindow, 901);
	SendMessage(h, EM_SCROLLCARET, 0, 0);
	SendMessage(h, EM_REPLACESEL,0, (LPARAM)t2);
	SendMessage(h, EM_REPLACESEL, 0, (LPARAM)L"\r\n");
	}

typedef struct _SUBFACTOR_TEXT {
	WINBIO_BIOMETRIC_SUBTYPE SubFactor;
	LPCTSTR Text;
	} SUBFACTOR_TEXT, *PSUBFACTOR_TEXT;

static const SUBFACTOR_TEXT g_SubFactorText[] = {
		{ WINBIO_SUBTYPE_NO_INFORMATION,             _T("(No information)") },
		{ WINBIO_ANSI_381_POS_RH_THUMB,              _T("RH thumb") },
		{ WINBIO_ANSI_381_POS_RH_INDEX_FINGER,       _T("RH index finger") },
		{ WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER,      _T("RH middle finger") },
		{ WINBIO_ANSI_381_POS_RH_RING_FINGER,        _T("RH ring finger") },
		{ WINBIO_ANSI_381_POS_RH_LITTLE_FINGER,      _T("RH little finger") },
		{ WINBIO_ANSI_381_POS_LH_THUMB,              _T("LH thumb") },
		{ WINBIO_ANSI_381_POS_LH_INDEX_FINGER,       _T("LH index finger") },
		{ WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER,      _T("LH middle finger") },
		{ WINBIO_ANSI_381_POS_LH_RING_FINGER,        _T("LH ring finger") },
		{ WINBIO_ANSI_381_POS_LH_LITTLE_FINGER,      _T("LH little finger") },
		{ WINBIO_SUBTYPE_ANY,                        _T("Any finger") },
	};
static const SIZE_T k_SubFactorTextTableSize = sizeof(g_SubFactorText) / sizeof(SUBFACTOR_TEXT);

typedef struct _REJECT_DETAIL_TEXT {
	WINBIO_REJECT_DETAIL RejectDetail;
	LPCTSTR Text;
	} REJECT_DETAIL_TEXT, *PREJECT_DETAIL_TEXT;

static const REJECT_DETAIL_TEXT g_RejectDetailText[] = {
		{ WINBIO_FP_TOO_HIGH,        _T("Scan your fingerprint a little lower.") },
		{ WINBIO_FP_TOO_LOW,         _T("Scan your fingerprint a little higher.") },
		{ WINBIO_FP_TOO_LEFT,        _T("Scan your fingerprint more to the right.") },
		{ WINBIO_FP_TOO_RIGHT,       _T("Scan your fingerprint more to the left.") },
		{ WINBIO_FP_TOO_FAST,        _T("Scan your fingerprint more slowly.") },
		{ WINBIO_FP_TOO_SLOW,        _T("Scan your fingerprint more quickly.") },
		{ WINBIO_FP_POOR_QUALITY,    _T("The quality of the fingerprint scan was not sufficient to make a match.  Check to make sure the sensor is clean.") },
		{ WINBIO_FP_TOO_SKEWED,      _T("Hold your finger flat and straight when scanning your fingerprint.") },
		{ WINBIO_FP_TOO_SHORT,       _T("Use a longer stroke when scanning your fingerprint.") },
		{ WINBIO_FP_MERGE_FAILURE,   _T("Unable to merge samples into a single enrollment. Try to repeat the enrollment procedure from the beginning.") },
	};
static const SIZE_T k_RejectDetailTextTableSize = sizeof(g_RejectDetailText) / sizeof(REJECT_DETAIL_TEXT);



LPCTSTR
ConvertRejectDetailToString(
	__in WINBIO_REJECT_DETAIL RejectDetail
)
	{
	SIZE_T index = 0;
	for (index = 0; index < k_RejectDetailTextTableSize; ++index)
		{
		if (g_RejectDetailText[index].RejectDetail == RejectDetail)
			{
			return g_RejectDetailText[index].Text;
			}
		}
	return _T("Reason for failure couldn't be diagnosed.");
	}

LPCTSTR
ConvertSubFactorToString(
	__in WINBIO_BIOMETRIC_SUBTYPE SubFactor
)
	{
	SIZE_T index = 0;
	for (index = 0; index < k_SubFactorTextTableSize; ++index)
		{
		if (g_SubFactorText[index].SubFactor == SubFactor)
			{
			return g_SubFactorText[index].Text;
			}
		}
	return _T("<Unknown>");
	}


std::wstring displayIdentity(
	__in PWINBIO_IDENTITY Identity,
	__in WINBIO_BIOMETRIC_SUBTYPE SubFactor
)
	{
	std::wstring a;
	wchar_t aa[1000] = { 0 };
	swprintf_s(aa,1000,_T("\n- Identity: "));
	a += aa;

	switch (Identity->Type)
		{
		case WINBIO_ID_TYPE_NULL:
			swprintf_s(aa, 1000, _T("NULL value\n"));
			a += aa;
			break;

		case WINBIO_ID_TYPE_WILDCARD:
			swprintf_s(aa, 1000, _T("WILDCARD value\n"));
			a += aa;
			if (Identity->Value.Wildcard != WINBIO_IDENTITY_WILDCARD)
				{
				swprintf_s(aa, 1000,
					_T("\n*** Error: Invalid wildcard marker (0x%08x)\n"),
					Identity->Value.Wildcard
				);
				a += aa;
				}
			break;

		case WINBIO_ID_TYPE_GUID:
			swprintf_s(aa, 1000, _T("GUID\n"));
			a += aa;
			swprintf_s(aa, 1000,
				_T("    Value:      {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n"),
				Identity->Value.TemplateGuid.Data1,
				Identity->Value.TemplateGuid.Data2,
				Identity->Value.TemplateGuid.Data3,
				Identity->Value.TemplateGuid.Data4[0],
				Identity->Value.TemplateGuid.Data4[1],
				Identity->Value.TemplateGuid.Data4[2],
				Identity->Value.TemplateGuid.Data4[3],
				Identity->Value.TemplateGuid.Data4[4],
				Identity->Value.TemplateGuid.Data4[5],
				Identity->Value.TemplateGuid.Data4[6],
				Identity->Value.TemplateGuid.Data4[7]
			);
			a += aa;
			break;

		case WINBIO_ID_TYPE_SID:
		{
			swprintf_s(aa, 1000, L"SID value: %S\n", Identity->Value.AccountSid.Data);
			a += aa;
			break;
		}
		default:
			swprintf_s(aa, 1000, _T("(Invalid type)\n"));
			a += aa;
			// invalid type
			break;
		}
	swprintf_s(aa, 1000,
		_T("    Subfactor:  %s\n"),
		ConvertSubFactorToString(SubFactor)
	);
	a += aa;
	return a;
	}


LRESULT CALLBACK Main_DP(HWND hh, UINT mm, WPARAM ww, LPARAM ll)
	{
	wchar_t fx[1000] = {};
	switch (mm)
		{
		case WM_CREATE:
			{
			CreateWindowEx(0, WC_EDIT, L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_WANTRETURN | ES_READONLY | WS_VSCROLL, 0, 0, 0, 0, hh, (HMENU)901, 0, 0);
			SendMessage(hh, WM_SIZE, 0, 0);
			break;
			}

		case WM_SIZE:
			{
			RECT rc;
			GetClientRect(hh, &rc);
			SetWindowPos(GetDlgItem(hh, 901), 0, 0, 0, rc.right, rc.bottom, SWP_SHOWWINDOW);
			return 0;
			}

		case WM_APP + 1:
		{
			WINBIO_E_INCORRECT_SESSION_TYPE;
			WINBIO_ASYNC_RESULT* ar = (WINBIO_ASYNC_RESULT*)ll;
			if (FAILED(ar->ApiStatus))
				swprintf_s(fx, 1000, L"Fail 0x%X - Operation %i", ar->ApiStatus, ar->Operation);
			else
				swprintf_s(fx, 1000, L"OK - Operation %i",ar->Operation);
			AddMessage(fx);
			
			__noop;
			return 0;
		}
		case WM_COMMAND:
			{
			int LW = LOWORD(ww);
			if (LW >= 701 && LW <= 799)
			{
				fp.SetType(fp.GetUnits()[LW - 701].BiometricFactor);
				auto g = GUID_DB_MY;
				g.Data4[7] = (unsigned char)(LW - 701 + 0x30);
				fp.SetDB(g);
				Unit = LW - 701;
				swprintf_s(fx, 1000, L"Sensor Selected: %s", fp.GetUnits()[LW - 701].Description);
				AddMessage(fx);
				return 0;
			}
			if (LW == 151)
			{
				SetWindowText(GetDlgItem(hh, 901), L"");
				return 0;
			}
			if (LW == 199)
				{
				SendMessage(hh, WM_CLOSE, 0, 0);
				return 0;
				}

			if (LW == 213)
			{
				fp.SetMine(false);
				return SendMessage(hh, WM_COMMAND, 203, 0xFF);
			}

			if (LW == 201)
				{
				hr = fp.Register(Unit);
				if (hr == E_ACCESSDENIED)
					{
					wchar_t f[1000] = { 0 };
					GetModuleFileName(0, f, 1000);
					wchar_t f2[100] = { 0 };
					swprintf_s(f2, 100, L"/register %i", Unit);
					RunAsAdmin(hh, f, f2);
					return 0;
					}

				if (FAILED(hr))
					AddMessage( L"Registration failed");
				else
					AddMessage(L"Registration succeeded");
				}
			if (LW == 202)
				{
				hr = fp.Unregister(Unit);
				if (hr == E_ACCESSDENIED)
					{
					wchar_t f[1000] = { 0 };
					GetModuleFileName(0, f, 1000);
					wchar_t f2[100] = { 0 };
					swprintf_s(f2, 100, L"/unregister %i", Unit);
					RunAsAdmin(hh, f, f2);
					return 0;
					}

				if (FAILED(hr))
					AddMessage(L"Unregistration failed");
				else
					AddMessage( L"Unregistration succeeded");
				}
			if (LW == 203)
				{
				if (ll != 0xFF)
					fp.SetMine(true);
				hr = fp.Open(Unit,hh,WM_APP + 1);
				if (FAILED(hr))
					AddMessage( L"Opening failed");
				else
					AddMessage( L"Opening succeeded");
				}
			if (LW == 204)
				{
				hr = fp.Close();
				AddMessage( L"Closed");
				}
			if (LW == 205)
				{
				WINBIO_UNIT_ID u = 0; 
				AddMessage( L"Touch the sensor please...");
				hr = fp.Locate(u);
				if (fp.IsAsync())
					return 0;
				if (FAILED(hr))
					AddMessage( L"Locating failed");
				else
					AddMessage( L"Locating completed");
				}
		
			if (LW >= 230 && LW <= 239)
				{
				UCHAR s = 0;
				if (LW == 230)
					s = WINBIO_ANSI_381_POS_RH_THUMB;
				if (LW == 231)
					s = WINBIO_ANSI_381_POS_RH_INDEX_FINGER;
				if (LW == 232)
					s = WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER;
				if (LW == 233)
					s = WINBIO_ANSI_381_POS_RH_RING_FINGER;
				if (LW == 234)
					s = WINBIO_ANSI_381_POS_RH_LITTLE_FINGER;
				if (LW == 235)
					s = WINBIO_ANSI_381_POS_LH_THUMB;
				if (LW == 236)
					s = WINBIO_ANSI_381_POS_LH_INDEX_FINGER;
				if (LW == 237)
					s = WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER;
				if (LW == 238)
					s = WINBIO_ANSI_381_POS_LH_RING_FINGER;
				if (LW == 239)
					s = WINBIO_ANSI_381_POS_LH_LITTLE_FINGER;

				auto cb = [](SIZE_T, HRESULT hrt, WINBIO_REJECT_DETAIL) -> HRESULT
					{
					if (FAILED(hrt))
						return hrt;
					if (SUCCEEDED(hr))
						AddMessage(L"Sample captured");
					if (hrt == WINBIO_I_MORE_DATA)
						AddMessage( L"More data required. Please reswipe");
					return hrt;
					};

				AddMessage( L"Please swipe your finger");
				auto enr = fp.Enroll(false,s,Unit,cb);
				if (fp.IsAsync())
					return 0;
				if (FAILED(std::get<0>(enr)))
					{
					AddMessage( L"Enroll failed");
					auto str = ConvertRejectDetailToString(std::get<1>(enr));
					AddMessage( str);
					}
				else
					{
					AddMessage( L"Enroll completed");
					auto str = displayIdentity(&std::get<3>(enr),s);
					LastID = std::get<3>(enr);
					LastSub = s;
					AddMessage( str.c_str());
					}
				}

		
			if (LW == 206)
				{
				auto cb = [](SIZE_T, HRESULT hrt, WINBIO_REJECT_DETAIL) -> HRESULT
					{
					if (FAILED(hrt))
						return hrt;
					if (SUCCEEDED(hr))
						AddMessage( L"Sample captured");
					if (hrt == WINBIO_I_MORE_DATA)
						AddMessage( L"More data required. Please reswipe");
					return hrt;
					};

				AddMessage( L"Please swipe your finger");
				auto ide = fp.Identify(Unit);
				if (fp.IsAsync())
					return 0;
				if (FAILED(std::get<0>(ide)))
					{
					AddMessage( L"Identification failed");
					auto str = ConvertRejectDetailToString(std::get<1>(ide));
					AddMessage(str);
					}
				else
					{
					AddMessage( L"Identification completed");
					LastID = std::get<3>(ide);
					LastSub = std::get<2>(ide);
					auto str = displayIdentity(&std::get<3>(ide), std::get<2>(ide));
					AddMessage( str.c_str());
					}
				}

			if (LW == 207)
				{
				hr = fp.Delete(0,LastID,LastSub);
				if (FAILED(hr))
					AddMessage( L"LastID deletion failed");
				else
					AddMessage( L"LastID deletion completed");
				}

			if (LW == 208)
				{
				AddMessage(L"Please swipe your finger");
				auto e = fp.Verify(LastID, LastSub);
				if (fp.IsAsync())
					return 0;
				if (FAILED(std::get<0>(e)))
					{
					AddMessage(L"LastID verification failed");
					auto str = ConvertRejectDetailToString(std::get<1>(e));
					AddMessage(str);
					}
				else
					{
					AddMessage(L"LastID verification completed");
					}
				}

			return 0;
			}



		case WM_CLOSE:
			{
			DestroyWindow(hh);
			return 0;
			}

		case WM_DESTROY:
			{
			PostQuitMessage(0);
			return 0;
			}
		}
	return DefWindowProc(hh, mm, ww, ll);
	}



int __stdcall WinMain(HINSTANCE h, HINSTANCE, LPSTR t, int)
	{
	CoInitializeEx(0, COINIT_APARTMENTTHREADED);

	INITCOMMONCONTROLSEX icex = { 0 };
	icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_DATE_CLASSES | ICC_WIN95_CLASSES;
	icex.dwSize = sizeof(icex);
	InitCommonControlsEx(&icex);
	InitCommonControls();

	hAppInstance = h;

	fp.Enum();
	if (strlen(t) && strstr(t, "/register"))
		{
		Unit = atoi(__argv[2]);
		fp.SetType(fp.GetUnits()[Unit].BiometricFactor);
		auto g = GUID_DB_MY;
		g.Data4[7] = (unsigned char)(Unit + 0x30);
		fp.SetDB(g);
		hr = fp.Register(Unit);
		if (FAILED(hr))
			MessageBox(0,L"Registration failed", L"" , MB_OK);
		else
			MessageBox(0, L"Registration succeeded",L"",  MB_OK);
		return 0;
		}
	if (strlen(t) && strstr(t, "/unregister"))
		{
		Unit = atoi(__argv[2]);
		fp.SetType(fp.GetUnits()[Unit].BiometricFactor);
		auto g = GUID_DB_MY;
		g.Data4[7] = (unsigned char)(Unit + 0x30);
		fp.SetDB(g);
		hr = fp.Unregister(Unit);
		if (FAILED(hr))
			MessageBox(0, L"Unregistration failed", L"", MB_OK);
		else
			MessageBox(0, L"Unregistration succeeded", L"", MB_OK);
		return 0;
		}

	WNDCLASSEX wClass = { 0 };
	wClass.cbSize = sizeof(wClass);

	wClass.style = CS_DBLCLKS | CS_HREDRAW | CS_VREDRAW | CS_PARENTDC;
	wClass.lpfnWndProc = (WNDPROC)Main_DP;
	wClass.hInstance = h;
	wClass.hIcon = 0;
	wClass.hCursor = LoadCursor(0, IDC_ARROW);
	wClass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wClass.lpszClassName = _T("CLASS");
	wClass.hIconSm = 0;
	RegisterClassEx(&wClass);

	MainWindow = CreateWindowEx(0,
		_T("CLASS"),
		L"FingerPrintf Demo",
		WS_OVERLAPPEDWINDOW | WS_CLIPSIBLINGS |
		WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		0,LoadMenu(h,L"MENU_1"), h, 0);


	auto m = GetMenu(MainWindow);
	auto hm = GetSubMenu(m, 1);
	for (size_t i = 0 ; i < fp.GetUnits().size() ; i++)
	{
		auto& u = fp.GetUnits()[i];
		AppendMenu(hm, MF_STRING, 701 + i, (LPCWSTR)u.Description);
	}
	DrawMenuBar(MainWindow);
	ShowWindow(MainWindow, SW_SHOW);


	MSG msg;
	auto a = LoadAccelerators(h, L"MENU_1");
	while (GetMessage(&msg, 0, 0, 0))
		{
		if (TranslateAccelerator(MainWindow, a, &msg))
			continue;
		TranslateMessage(&msg);
		DispatchMessage(&msg);
		}

	return 0;
}