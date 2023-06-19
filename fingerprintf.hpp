#include <WinBio.h>
#pragma comment(lib,"winbio.lib")


class FINGERPRINTF
	{
	private:
		HRESULT hr = S_OK;
		bool Mine = false;
		WINBIO_SESSION_HANDLE sessionHandle = NULL;
		std::vector<WINBIO_UNIT_SCHEMA> units;
		GUID PRIVATE_POOL_DATABASE_ID = GUID_NULL;
		bool Async = false;

		WINBIO_BIOMETRIC_TYPE TheType = WINBIO_TYPE_FINGERPRINT;

#ifndef ARGUMENT_PRESENT
#define ARGUMENT_PRESENT(x) (((x) != NULL))
#endif
		// Helpers from MSDN
		typedef struct _POOL_CONFIGURATION {
			ULONG ConfigurationFlags;
			ULONG DatabaseAttributes;
			WINBIO_UUID DatabaseId;
			WINBIO_UUID DataFormat;
			WCHAR SensorAdapter[MAX_PATH];
			WCHAR EngineAdapter[MAX_PATH];
			WCHAR StorageAdapter[MAX_PATH];
			} POOL_CONFIGURATION, *PPOOL_CONFIGURATION;



		inline  bool
			IsKeyNameNumeric(
				__in LPWSTR KeyName,
				__in DWORD KeyNameLength    // in characters
			)
			{
			if (KeyNameLength == 0)
				{
				return false;
				}
			else
				{
				for (DWORD i = 0; i < KeyNameLength; ++i)
					{
					if (!iswdigit(KeyName[i]))
						{
						return false;
						}
					}
				return true;
				}
			}

		//-----------------------------------------------------------------------------

		HRESULT
			CreateCompatibleConfiguration(
				__in WINBIO_UNIT_SCHEMA* UnitSchema,
				__out POOL_CONFIGURATION* Configuration, HKEY root = HKEY_LOCAL_MACHINE
			)
			{
			hr = S_OK;
			if (!ARGUMENT_PRESENT(UnitSchema) ||
				!ARGUMENT_PRESENT(Configuration))
				{
				return E_POINTER;
				}

			WINBIO_STORAGE_SCHEMA *storageArray = NULL;
			SIZE_T storageCount = 0;
			hr = WinBioEnumDatabases(TheType, &storageArray, &storageCount);
			if (FAILED(hr))
				{
				return hr;
				}

			std::wstring regPath = L"System\\CurrentControlSet\\Enum\\";
			regPath += UnitSchema->DeviceInstanceId;
			regPath += L"\\Device Parameters\\WinBio\\Configurations";

			HKEY configListKey = NULL;
			LONG regStatus = RegOpenKeyExW(
				root,
				regPath.c_str(),
				0,
				KEY_READ,
				&configListKey
			);
			if (regStatus != ERROR_SUCCESS)
				{
				WinBioFree(storageArray);
				storageArray = NULL;
				storageCount = 0;
				return HRESULT_FROM_WIN32(regStatus);
				}

			DWORD subkeyIndex = 0;
			for (;;)
				{
				hr = S_OK;

				DWORD sensorMode = 0;
				ULONG configFlags = 0;
				DWORD systemSensor = 0;
				WINBIO_UUID dataFormat = {};
				ULONG attributes = 0;
				WCHAR sensorAdapter[MAX_PATH] = {};
				WCHAR engineAdapter[MAX_PATH] = {};
				WCHAR storageAdapter[MAX_PATH] = {};

				WCHAR subkeyName[MAX_PATH] = {};
				DWORD subkeyNameLength = ARRAYSIZE(subkeyName);
				regStatus = RegEnumKeyExW(
					configListKey,
					subkeyIndex,
					(LPWSTR)&subkeyName,
					&subkeyNameLength,
					NULL,
					NULL,
					NULL,
					NULL
				);
				if (regStatus != ERROR_SUCCESS)
					{
					if (regStatus == ERROR_NO_MORE_ITEMS)
						{
						hr = S_OK;
						}
					else
						{
						hr = HRESULT_FROM_WIN32(regStatus);
						}
					break;
					}

				if (IsKeyNameNumeric(subkeyName, subkeyNameLength))
					{
					std::wstring configKeyPath = regPath + L"\\";
					configKeyPath += subkeyName;

					HKEY configKey = NULL;
					hr = HRESULT_FROM_WIN32(
						RegOpenKeyExW(
							root,
							configKeyPath.c_str(),
							0,
							KEY_READ,
							&configKey
						));
					if (SUCCEEDED(hr))
						{
						/*
						Extract values in this configuration
						SensorMode              - REG_DWORD
						SystemSensor            - REG_DWORD
						DatabaseId              - REG_SZ
						SensorAdapterBinary     - REG_SZ
						EngineAdapterBinary     - REG_SZ
						StorageAdapterBinary    - REG_SZ
						*/
						DWORD dataSize = sizeof(sensorMode);
						hr = HRESULT_FROM_WIN32(
							RegGetValueW(
								configKey,
								NULL,
								L"SensorMode",
								RRF_RT_REG_DWORD,
								NULL,
								&sensorMode,
								&dataSize
							));
						if (SUCCEEDED(hr))
							{
							switch (sensorMode)
								{
								case WINBIO_SENSOR_BASIC_MODE:
									configFlags = WINBIO_FLAG_BASIC;
									break;

								case WINBIO_SENSOR_ADVANCED_MODE:
									configFlags = WINBIO_FLAG_ADVANCED;
									break;

								default:
									configFlags = WINBIO_FLAG_DEFAULT;
									break;
								}
							}

						if (SUCCEEDED(hr))
							{
							dataSize = sizeof(systemSensor);
							hr = HRESULT_FROM_WIN32(
								RegGetValueW(
									configKey,
									NULL,
									L"SystemSensor",
									RRF_RT_REG_DWORD,
									NULL,
									&systemSensor,
									&dataSize
								));
							}

						if (SUCCEEDED(hr))
							{
							WCHAR databaseIdString[40] = {};
							dataSize = sizeof(databaseIdString);
							hr = HRESULT_FROM_WIN32(
								RegGetValueW(
									configKey,
									NULL,
									L"DatabaseId",
									RRF_RT_REG_SZ,
									NULL,
									&databaseIdString,
									&dataSize
								));
							if (SUCCEEDED(hr))
								{
								// convert string to GUID and find that GUID 
								// in database list; capture corresponding 
								// data-format GUID
								WINBIO_UUID databaseIdGuid;
								ConvertStringToUuid(databaseIdString, &databaseIdGuid);

								bool databaseFound = false;
								for (SIZE_T i = 0; i < storageCount; ++i)
									{
									if (storageArray[i].DatabaseId == databaseIdGuid)
										{
										dataFormat = storageArray[i].DataFormat;
										attributes = storageArray[i].Attributes;
										databaseFound = true;
										break;
										}
									}
								if (!databaseFound)
									{
									hr = WINBIO_E_DATABASE_CANT_FIND;
									}
								}
							}

						if (SUCCEEDED(hr))
							{
							dataSize = sizeof(sensorAdapter);
							hr = HRESULT_FROM_WIN32(
								RegGetValueW(
									configKey,
									NULL,
									L"SensorAdapterBinary",
									RRF_RT_REG_SZ,
									NULL,
									&sensorAdapter,
									&dataSize
								));
							}

						if (SUCCEEDED(hr))
							{
							dataSize = sizeof(engineAdapter);
							hr = HRESULT_FROM_WIN32(
								RegGetValueW(
									configKey,
									NULL,
									L"EngineAdapterBinary",
									RRF_RT_REG_SZ,
									NULL,
									&engineAdapter,
									&dataSize
								));
							}

						if (SUCCEEDED(hr))
							{
							dataSize = sizeof(storageAdapter);
							hr = HRESULT_FROM_WIN32(
								RegGetValueW(
									configKey,
									NULL,
									L"StorageAdapterBinary",
									RRF_RT_REG_SZ,
									NULL,
									&storageAdapter,
									&dataSize
								));
							}

						RegCloseKey(configKey);
						configKey = NULL;
						}
					}
				if (SUCCEEDED(hr))
					{
					if (systemSensor)
						{
						// copy results to output structure - we only want this
						// one if it's a derived from a system sensor config
						Configuration->ConfigurationFlags = configFlags;
						Configuration->DatabaseAttributes = attributes;
						Configuration->DataFormat = dataFormat;
						wcscpy_s(Configuration->SensorAdapter, MAX_PATH, sensorAdapter);
						wcscpy_s(Configuration->EngineAdapter, MAX_PATH, engineAdapter);
						wcscpy_s(Configuration->StorageAdapter, MAX_PATH, storageAdapter);
						break;
						}
					else
						{
						++subkeyIndex;
						}
					}
				else
					{
					break;
					}
				}
			RegCloseKey(configListKey);
			configListKey = NULL;

			if (storageArray != NULL)
				{
				WinBioFree(storageArray);
				storageArray = NULL;
				storageCount = 0;
				}

			return hr;
			}

		//-----------------------------------------------------------------------------

		HRESULT
			RegisterDatabase(
				__in WINBIO_STORAGE_SCHEMA* StorageSchema,HKEY root = HKEY_LOCAL_MACHINE
			)
			{
			/*
			HKLM\System\CurrentControlSet\Services\WbioSrvc\Databases\{guid} -- NOTE THE CURLY BRACES
			Attributes          - REG_DWORD
			AutoCreate          - REG_DWORD (1)
			AutoName            - REG_DWORD (1)     -- this is reset to zero when the service creates the DB
			BiometricType       - REG_DWORD (8)     -- TheType
			ConnectionString    - REG_SZ ""
			FilePath            - REG_SZ ""         -- set by service
			Format              - REG_SZ "guid"     -- NOTE: *NO* CURLY BRACES
			InitialSize         - REG_DWORD (32)
			*/
			hr = S_OK;

			if (!ARGUMENT_PRESENT(StorageSchema))
				{
				return E_POINTER;
				}

			WCHAR databaseKeyName[MAX_PATH] = {};
			if (!ConvertUuidToString(
				&StorageSchema->DatabaseId,
				databaseKeyName,
				ARRAYSIZE(databaseKeyName),
				true
			))
				{
				return E_INVALIDARG;
				}

			WCHAR dataFormat[MAX_PATH] = {};
			if (!ConvertUuidToString(
				&StorageSchema->DataFormat,
				dataFormat,
				ARRAYSIZE(dataFormat),
				false
			))
				{
				return E_INVALIDARG;
				}

			HKEY databaseListKey = NULL;
			hr = HRESULT_FROM_WIN32(
				RegOpenKeyExW(
					root,
					L"System\\CurrentControlSet\\Services\\WbioSrvc\\Databases",
					0,
					KEY_WRITE,
					&databaseListKey
				));
			if (FAILED(hr))
				{
				return hr;
				}

			HKEY newDatabaseKey = NULL;
			DWORD keyDisposition = 0;
			hr = HRESULT_FROM_WIN32(
				RegCreateKeyExW(
					databaseListKey,
					databaseKeyName,
					0,
					NULL,
					REG_OPTION_NON_VOLATILE,
					KEY_WRITE,
					NULL,
					&newDatabaseKey,
					&keyDisposition
				));
			if (SUCCEEDED(hr))
				{
				if (keyDisposition == REG_OPENED_EXISTING_KEY)
					{
					hr = WINBIO_E_DATABASE_ALREADY_EXISTS;
					}

				if (SUCCEEDED(hr))
					{
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newDatabaseKey,
							L"Attributes",
							0,
							REG_DWORD,
							(LPBYTE)&StorageSchema->Attributes,
							sizeof(StorageSchema->Attributes)
						));
					}

				if (SUCCEEDED(hr))
					{
					DWORD autoCreate = 1;
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newDatabaseKey,
							L"AutoCreate",
							0,
							REG_DWORD,
							(LPBYTE)&autoCreate,
							sizeof(autoCreate)
						));
					}

				if (SUCCEEDED(hr))
					{
					DWORD autoName = 1;
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newDatabaseKey,
							L"AutoName",
							0,
							REG_DWORD,
							(LPBYTE)&autoName,
							sizeof(autoName)
						));
					}

				if (SUCCEEDED(hr))
					{
					WINBIO_BIOMETRIC_TYPE biometricType = TheType;
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newDatabaseKey,
							L"BiometricType",
							0,
							REG_DWORD,
							(LPBYTE)&biometricType,
							sizeof(biometricType)
						));
					}

				if (SUCCEEDED(hr))
					{
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newDatabaseKey,
							L"ConnectionString",
							0,
							REG_SZ,
							(LPBYTE)L"",
							sizeof(WCHAR)
						));
					}

				if (SUCCEEDED(hr))
					{
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newDatabaseKey,
							L"FilePath",
							0,
							REG_SZ,
							(LPBYTE)L"",
							sizeof(WCHAR)
						));
					}

				if (SUCCEEDED(hr))
					{
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newDatabaseKey,
							L"Format",
							0,
							REG_SZ,
							(LPBYTE)dataFormat,
							(DWORD)((wcsnlen_s(
								dataFormat,
								ARRAYSIZE(dataFormat)) + 1) * sizeof(WCHAR))
						));
					}

				if (SUCCEEDED(hr))
					{
					DWORD initialSize = 32;
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newDatabaseKey,
							L"InitialSize",
							0,
							REG_DWORD,
							(LPBYTE)&initialSize,
							sizeof(initialSize)
						));
					}

				RegCloseKey(newDatabaseKey);
				newDatabaseKey = NULL;
				}

			RegCloseKey(databaseListKey);
			databaseListKey = NULL;
			return hr;
			}

		//-----------------------------------------------------------------------------

		HRESULT
			UnregisterDatabase(
				__in WINBIO_UUID *DatabaseId, HKEY root = HKEY_LOCAL_MACHINE
			)
			{
			hr = S_OK;

			if (!ARGUMENT_PRESENT(DatabaseId))
				{
				return E_POINTER;
				}

			WCHAR databaseKeyName[MAX_PATH] = {};
			if (!ConvertUuidToString(
				DatabaseId,
				databaseKeyName,
				ARRAYSIZE(databaseKeyName),
				true
			))
				{
				return E_INVALIDARG;
				}

			WINBIO_STORAGE_SCHEMA *storageArray = NULL;
			SIZE_T storageCount = 0;
			hr = WinBioEnumDatabases(TheType, &storageArray, &storageCount);
			if (SUCCEEDED(hr))
				{
				WINBIO_STORAGE_SCHEMA *storageSchema = NULL;
				for (SIZE_T i = 0; i < storageCount; ++i)
					{
					if (storageArray[i].DatabaseId == *DatabaseId)
						{
						storageSchema = &storageArray[i];
						break;
						}
					}

				if (storageSchema == NULL)
					{
					hr = WINBIO_E_DATABASE_CANT_FIND;
					}
				else
					{
					HKEY databaseListKey = NULL;
					hr = HRESULT_FROM_WIN32(
						RegOpenKeyExW(
							root,
							L"System\\CurrentControlSet\\Services\\WbioSrvc\\Databases",
							0,
							KEY_WRITE,
							&databaseListKey
						));
					if (SUCCEEDED(hr))
						{
						hr = HRESULT_FROM_WIN32(
							RegDeleteKeyExW(
								databaseListKey,
								databaseKeyName,
								KEY_WOW64_64KEY,
								0
							));
						if (SUCCEEDED(hr) &&
							wcsnlen_s(storageSchema->FilePath, ARRAYSIZE(storageSchema->FilePath)) > 0)
							{
							// delete the database file
							if (!DeleteFileW(storageSchema->FilePath))
								{
								hr = HRESULT_FROM_WIN32(GetLastError());
								}
							}

						RegCloseKey(databaseListKey);
						databaseListKey = NULL;
						}
					}

				WinBioFree(storageArray);
				storageArray = NULL;
				storageCount = 0;
				}

			return hr;
			}

		//-----------------------------------------------------------------------------

		HRESULT
			RegisterPrivateConfiguration(
				__in WINBIO_UNIT_SCHEMA* UnitSchema,
				__in POOL_CONFIGURATION* Configuration, HKEY root = HKEY_LOCAL_MACHINE
			)
			{
			hr = S_OK;

			if (!ARGUMENT_PRESENT(UnitSchema) ||
				!ARGUMENT_PRESENT(Configuration))
				{
				return E_POINTER;
				}

			DWORD sensorMode = 0;
			if (Configuration->ConfigurationFlags & WINBIO_FLAG_BASIC)
				{
				sensorMode = WINBIO_SENSOR_BASIC_MODE;
				}
			else if (Configuration->ConfigurationFlags & WINBIO_FLAG_ADVANCED)
				{
				sensorMode = WINBIO_SENSOR_ADVANCED_MODE;
				}
			else
				{
				return WINBIO_E_CONFIGURATION_FAILURE;
				}

			WCHAR databaseId[MAX_PATH];
			if (!ConvertUuidToString(
				&Configuration->DatabaseId,
				databaseId,
				ARRAYSIZE(databaseId),
				false
			))
				{
				return E_INVALIDARG;
				}

			std::wstring regPath = L"System\\CurrentControlSet\\Enum\\";
			regPath += UnitSchema->DeviceInstanceId;
			regPath += L"\\Device Parameters\\WinBio\\Configurations";

			HKEY configListKey = NULL;
			LONG regStatus = RegOpenKeyExW(
				root,
				regPath.c_str(),
				0,
				KEY_READ | KEY_WRITE,
				&configListKey
			);
			if (regStatus != ERROR_SUCCESS)
				{
				return HRESULT_FROM_WIN32(regStatus);
				}

			LONG highestConfigKeyValue = -1;
			DWORD subkeyIndex = 0;
			for (;;)
				{
				hr = S_OK;

				WCHAR subkeyName[MAX_PATH] = {};
				DWORD subkeyNameLength = ARRAYSIZE(subkeyName);
				regStatus = RegEnumKeyExW(
					configListKey,
					subkeyIndex,
					(LPWSTR)&subkeyName,
					&subkeyNameLength,
					NULL,
					NULL,
					NULL,
					NULL
				);
				if (regStatus != ERROR_SUCCESS)
					{
					if (regStatus == ERROR_NO_MORE_ITEMS)
						{
						hr = S_OK;
						}
					else
						{
						hr = HRESULT_FROM_WIN32(regStatus);
						}
					break;
					}

				if (IsKeyNameNumeric(subkeyName, subkeyNameLength))
					{
					// See if the config we're trying to register 
					// is already registered for this sensor
					bool collision = false;
					hr = CompareConfiguration(
						configListKey,
						subkeyName,
						Configuration,
						&collision
					);
					if (SUCCEEDED(hr) && collision)
						{
						hr = WINBIO_E_CONFIGURATION_FAILURE;
						}
					if (FAILED(hr))
						{
						break;
						}

					// Convert key name to number and see if 
					// it's bigger than the highest one we've
					// seen so far; if so, keep it
					LONG thisKey = _wtoi(subkeyName);
					highestConfigKeyValue = max(thisKey, highestConfigKeyValue);
					}
				++subkeyIndex;
				}

			if (SUCCEEDED(hr))
				{
				WCHAR newConfigKeyName[20] = {};
				_itow_s((highestConfigKeyValue + 1), newConfigKeyName, ARRAYSIZE(newConfigKeyName), 10);

				HKEY newConfigKey = NULL;
				DWORD keyDisposition = 0;
				hr = HRESULT_FROM_WIN32(
					RegCreateKeyExW(
						configListKey,
						newConfigKeyName,
						0,
						NULL,
						REG_OPTION_NON_VOLATILE,
						KEY_WRITE,
						NULL,
						&newConfigKey,
						&keyDisposition
					));
				if (SUCCEEDED(hr))
					{
					/*
					Create values for this configuration
					SensorMode              - REG_DWORD
					SystemSensor            - REG_DWORD (always zero for private configs)
					DatabaseId              - REG_SZ
					SensorAdapterBinary     - REG_SZ
					EngineAdapterBinary     - REG_SZ
					StorageAdapterBinary    - REG_SZ
					*/
					hr = HRESULT_FROM_WIN32(
						RegSetValueExW(
							newConfigKey,
							L"SensorMode",
							0,
							REG_DWORD,
							(LPBYTE)&sensorMode,
							sizeof(sensorMode)
						));

					if (SUCCEEDED(hr))
						{
						DWORD sytemSensor = 0;
						hr = HRESULT_FROM_WIN32(
							RegSetValueExW(
								newConfigKey,
								L"SystemSensor",
								0,
								REG_DWORD,
								(LPBYTE)&sytemSensor,
								sizeof(sytemSensor)
							));
						}

					if (SUCCEEDED(hr))
						{
						hr = HRESULT_FROM_WIN32(
							RegSetValueExW(
								newConfigKey,
								L"DatabaseId",
								0,
								REG_SZ,
								(LPBYTE)databaseId,
								(DWORD)((wcsnlen_s(
									databaseId,
									ARRAYSIZE(databaseId)) + 1) * sizeof(WCHAR))
							));
						}

					if (SUCCEEDED(hr))
						{
						hr = HRESULT_FROM_WIN32(
							RegSetValueExW(
								newConfigKey,
								L"SensorAdapterBinary",
								0,
								REG_SZ,
								(LPBYTE)Configuration->SensorAdapter,
								(DWORD)((wcsnlen_s(
									Configuration->SensorAdapter,
									ARRAYSIZE(Configuration->SensorAdapter)) + 1) * sizeof(WCHAR))
							));
						}

					if (SUCCEEDED(hr))
						{
						hr = HRESULT_FROM_WIN32(
							RegSetValueExW(
								newConfigKey,
								L"EngineAdapterBinary",
								0,
								REG_SZ,
								(LPBYTE)Configuration->EngineAdapter,
								(DWORD)((wcsnlen_s(
									Configuration->EngineAdapter,
									ARRAYSIZE(Configuration->EngineAdapter)) + 1) * sizeof(WCHAR))
							));
						}

					if (SUCCEEDED(hr))
						{
						hr = HRESULT_FROM_WIN32(
							RegSetValueExW(
								newConfigKey,
								L"StorageAdapterBinary",
								0,
								REG_SZ,
								(LPBYTE)Configuration->StorageAdapter,
								(DWORD)((wcsnlen_s(
									Configuration->StorageAdapter,
									ARRAYSIZE(Configuration->StorageAdapter)) + 1) * sizeof(WCHAR))
							));
						}

					RegCloseKey(newConfigKey);
					newConfigKey = NULL;
					}
				}

			RegCloseKey(configListKey);
			configListKey = NULL;

			return hr;
			}

		//-----------------------------------------------------------------------------

		HRESULT
			UnregisterPrivateConfiguration(
				__in WINBIO_UNIT_SCHEMA* UnitSchema,
				__in WINBIO_UUID *DatabaseId,
				__out bool *ConfigurationRemoved, HKEY root = HKEY_LOCAL_MACHINE
			)
			{
			hr = S_OK;

			if (!ARGUMENT_PRESENT(UnitSchema) ||
				!ARGUMENT_PRESENT(DatabaseId))
				{
				return E_POINTER;
				}

			WCHAR targetDatabaseId[40];
			if (!ConvertUuidToString(
				DatabaseId,
				targetDatabaseId,
				ARRAYSIZE(targetDatabaseId),
				false
			))
				{
				return E_INVALIDARG;
				}

			std::wstring regPath = L"System\\CurrentControlSet\\Enum\\";
			regPath += UnitSchema->DeviceInstanceId;
			regPath += L"\\Device Parameters\\WinBio\\Configurations";

			HKEY configListKey = NULL;
			hr = HRESULT_FROM_WIN32(
				RegOpenKeyExW(
					root,
					regPath.c_str(),
					0,
					KEY_READ | KEY_WRITE,
					&configListKey
				));
			if (FAILED(hr))
				{
				return hr;
				}

			bool configurationRemoved = false;
			DWORD subkeyIndex = 0;
			for (;;)
				{
				hr = S_OK;

				WCHAR configKeyName[MAX_PATH] = {};
				DWORD configKeyNameLength = ARRAYSIZE(configKeyName);
				LONG regStatus = RegEnumKeyExW(
					configListKey,
					subkeyIndex,
					(LPWSTR)&configKeyName,
					&configKeyNameLength,
					NULL,
					NULL,
					NULL,
					NULL
				);
				if (regStatus != ERROR_SUCCESS)
					{
					if (regStatus == ERROR_NO_MORE_ITEMS)
						{
						hr = S_OK;
						}
					else
						{
						hr = HRESULT_FROM_WIN32(regStatus);
						}
					break;
					}

				if (IsKeyNameNumeric(configKeyName, configKeyNameLength))
					{
					WCHAR configDatabaseId[40] = {};
					DWORD dataSize = sizeof(configDatabaseId);
					hr = HRESULT_FROM_WIN32(
						RegGetValueW(
							configListKey,
							configKeyName,
							L"DatabaseId",
							RRF_RT_REG_SZ,
							NULL,
							&configDatabaseId,
							&dataSize
						));
					if (SUCCEEDED(hr) &&
						_wcsnicmp(configDatabaseId, targetDatabaseId, ARRAYSIZE(configDatabaseId)) == 0)
						{
						hr = HRESULT_FROM_WIN32(
							RegDeleteKeyExW(
								configListKey,
								configKeyName,
								KEY_WOW64_64KEY,
								0
							));
						if (SUCCEEDED(hr))
							{
							configurationRemoved = true;
							}
						}
					}
				if (SUCCEEDED(hr))
					{
					++subkeyIndex;
					}
				else
					{
					break;
					}
				}

			RegCloseKey(configListKey);
			configListKey = NULL;
			*ConfigurationRemoved = configurationRemoved;
			return hr;
			}

		//-----------------------------------------------------------------------------

		 HRESULT
			CompareConfiguration(
				__in HKEY SourceConfigList,
				__in LPWSTR SourceConfigKey,
				__in POOL_CONFIGURATION* TargetConfig,
				__out bool *IsEqual
			)
			{

			if (SourceConfigList == NULL)
				{
				return E_INVALIDARG;
				}

			if (!ARGUMENT_PRESENT(SourceConfigKey) ||
				!ARGUMENT_PRESENT(TargetConfig) ||
				!ARGUMENT_PRESENT(IsEqual))
				{
				return E_POINTER;
				}

			WCHAR targetDatabaseId[40];
			if (!ConvertUuidToString(
				&TargetConfig->DatabaseId,
				targetDatabaseId,
				ARRAYSIZE(targetDatabaseId),
				false
			))
				{
				return E_INVALIDARG;
				}

			HKEY srcConfig = NULL;
			hr = HRESULT_FROM_WIN32(
				RegOpenKeyExW(
					SourceConfigList,
					SourceConfigKey,
					0,
					KEY_READ,
					&srcConfig
				));
			if (SUCCEEDED(hr))
				{
				bool isEqual = true;

				WCHAR configDatabaseId[40] = {};
				DWORD dataSize = sizeof(configDatabaseId);
				hr = HRESULT_FROM_WIN32(
					RegGetValueW(
						srcConfig,
						NULL,
						L"DatabaseId",
						RRF_RT_REG_SZ,
						NULL,
						&configDatabaseId,
						&dataSize
					));
				if (SUCCEEDED(hr) &&
					_wcsnicmp(configDatabaseId, targetDatabaseId, ARRAYSIZE(configDatabaseId)) != 0)
					{
					isEqual = false;
					}

				RegCloseKey(srcConfig);
				srcConfig = NULL;

				if (SUCCEEDED(hr))
					{
					*IsEqual = isEqual;
					}
				}
			return hr;
			}

		//-----------------------------------------------------------------------------

		 bool
			ConvertStringToUuid(
				__in LPWSTR UuidString,
				__out WINBIO_UUID *Uuid
			)
			{
			int data1 = 0;
			int data2 = 0;
			int data3 = 0;
			int data40 = 0;
			int data41 = 0;
			int data42 = 0;
			int data43 = 0;
			int data44 = 0;
			int data45 = 0;
			int data46 = 0;
			int data47 = 0;
			int conversionCount = swscanf_s(
				UuidString,
				L"%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
				&data1,
				&data2,
				&data3,
				&data40,
				&data41,
				&data42,
				&data43,
				&data44,
				&data45,
				&data46,
				&data47
			);

			if (conversionCount != 11)
				{
				return false;
				}

			Uuid->Data1 = data1;
			Uuid->Data2 = (WORD)data2;
			Uuid->Data3 = (WORD)data3;
			Uuid->Data4[0] = (BYTE)data40;
			Uuid->Data4[1] = (BYTE)data41;
			Uuid->Data4[2] = (BYTE)data42;
			Uuid->Data4[3] = (BYTE)data43;
			Uuid->Data4[4] = (BYTE)data44;
			Uuid->Data4[5] = (BYTE)data45;
			Uuid->Data4[6] = (BYTE)data46;
			Uuid->Data4[7] = (BYTE)data47;

			return true;
			}

		//-----------------------------------------------------------------------------

		 bool isDatabaseInstalled(
			__in WINBIO_UUID *DatabaseId,
			__out WINBIO_UUID *DataFormat
		)
			{
			if (!ARGUMENT_PRESENT(DatabaseId) ||
				!ARGUMENT_PRESENT(DataFormat))
				{
				return false;
				}

			bool databaseInstalled = false;
			WINBIO_STORAGE_SCHEMA *storageArray = NULL;
			SIZE_T storageCount = 0;

			if (SUCCEEDED(
				WinBioEnumDatabases(
					TheType,
					&storageArray,
					&storageCount
				)))
				{
				for (SIZE_T i = 0; i < storageCount; ++i)
					{
					if (storageArray[i].DatabaseId == *DatabaseId)
						{
						*DataFormat = storageArray[i].DataFormat;
						databaseInstalled = true;
						break;
						}
					}

				WinBioFree(storageArray);
				storageArray = NULL;
				storageCount = 0;
				}

			return databaseInstalled;
			}

		 bool
			ConvertUuidToString(
				__in WINBIO_UUID *Uuid,
				__out LPWSTR UuidStringBuffer,
				__in SIZE_T UuidStringBufferLength,
				__in bool IncludeBraces
			)
			{
			 wchar_t w[100] = { 0 };
			 StringFromGUID2(*Uuid, w, 100);
			 if (!IncludeBraces)
			 {
				 w[wcslen(w) - 1] = 0;
				 wcscpy_s(UuidStringBuffer, UuidStringBufferLength, w + 1);
			 }
			 else
				 wcscpy_s(UuidStringBuffer, UuidStringBufferLength, w);
			 return true;
		 }

		 HRESULT InstallDatabase(SIZE_T selectedUnit)
			{
			WINBIO_UUID databaseId = PRIVATE_POOL_DATABASE_ID;
			WINBIO_UUID dataFormat = {};

			if (isDatabaseInstalled(&databaseId, &dataFormat))
				{
				return S_FALSE;
				}

			POOL_CONFIGURATION derivedConfig = {};
			hr = CreateCompatibleConfiguration(
				&units[selectedUnit],
				&derivedConfig
			);
			if (SUCCEEDED(hr))
				{
				WINBIO_STORAGE_SCHEMA storageSchema = {};
				storageSchema.DatabaseId = PRIVATE_POOL_DATABASE_ID;
				storageSchema.DataFormat = derivedConfig.DataFormat;
				storageSchema.Attributes = derivedConfig.DatabaseAttributes;
				hr = RegisterDatabase(&storageSchema);
				}
			return hr;
			}


		 HRESULT UninstallDatabase(int Unit)
			 {
			 WINBIO_UUID databaseId = PRIVATE_POOL_DATABASE_ID;
			 WINBIO_UUID dataFormat = {};

			 if (!isDatabaseInstalled(&databaseId, &dataFormat))
				 {
				 return S_FALSE;
				 }
				 for (SIZE_T i = 0; i < units.size() ; ++i)
					 {
					 if (i != Unit)
						 continue;
					 bool configRemoved = false;
					 hr = UnregisterPrivateConfiguration(
						 &units[i],
						 &databaseId,
						 &configRemoved
					 );
					 if (FAILED(hr))
						 {
						 break;
						 }
					 if (configRemoved)
						 {
						 }
				 }

			 if (SUCCEEDED(hr))
				 {
				 // Remove the database.
				 hr = UnregisterDatabase(&databaseId);
				 }
			 return hr;
			 }

		 //-----------------------------------------------------------------------------

		 HRESULT Add(SIZE_T selectedUnit)
			 {
			 WINBIO_UUID databaseId = PRIVATE_POOL_DATABASE_ID;
			 WINBIO_UUID dataFormat = {};

			 if (!isDatabaseInstalled(&databaseId, &dataFormat))
				 {
				 return E_NOINTERFACE;
				 }

			POOL_CONFIGURATION derivedConfig = {};
			hr = CreateCompatibleConfiguration(
				&units[selectedUnit],
				&derivedConfig
			);
			if (SUCCEEDED(hr))
				{
				derivedConfig.DatabaseId = PRIVATE_POOL_DATABASE_ID;
				hr = RegisterPrivateConfiguration(
					&units[selectedUnit],
					&derivedConfig
				);
				}
			 return hr;
			 }

		 //-----------------------------------------------------------------------------

		 HRESULT Remove(SIZE_T selectedUnit)
			 {
			 bool configRemoved = false;
				WINBIO_UUID targetDatabase = PRIVATE_POOL_DATABASE_ID;
				hr = UnregisterPrivateConfiguration(
					&units[selectedUnit],
					&targetDatabase,
					&configRemoved
				);
		     return hr;
			 }

		 bool RestartService()
		 {
			 bool B = 0;
			 auto s = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
			 if (s)
			 {
				 SC_HANDLE hS = OpenService(s, L"WBioSrvc", SC_MANAGER_ALL_ACCESS);
				 if (hS)
				 {
					 SERVICE_STATUS st = {};
					 ControlService(hS, SERVICE_CONTROL_STOP, &st);
					 Sleep(5000);
					 StartService(hS, 0, 0);
					 CloseServiceHandle(hS);
					 B = 1;
				 }
				 CloseServiceHandle(s);
			 }
			 return B;
		 }


		 //-----------------------------------------------------------------------------

	public:

		std::vector<WINBIO_UNIT_SCHEMA>& GetUnits() { return units; } const
		HRESULT Enum()
			{
			PWINBIO_UNIT_SCHEMA unitSchema = NULL;
			SIZE_T unitCount = 0;
			SIZE_T index = 0;

			// Enumerate the installed biometric units.
			hr = WinBioEnumBiometricUnits(WINBIO_TYPE_ANY, &unitSchema, &unitCount);
			if (FAILED(hr))
				return hr;
			for (index = 0; index < unitCount; ++index)
			{
				auto& s = unitSchema[index];
				units.push_back(s);
			}
			WinBioFree(unitSchema);
			return S_OK;
			}

		std::vector<WINBIO_BIOMETRIC_SUBTYPE> EnumEnrollments(size_t idx,WINBIO_IDENTITY& id)
		{
			WINBIO_BIOMETRIC_SUBTYPE* a = 0;
			SIZE_T sz = 100;
			WinBioEnumEnrollments(sessionHandle, units[idx].UnitId, &id, &a, &sz);
			std::vector<WINBIO_BIOMETRIC_SUBTYPE> s;
			for (size_t i = 0; i < sz; i++)
			{
				if (a[0])
					s.push_back(a[i]);
			}
			if (a)
				WinBioFree(a);
			return s;

		}

		HRESULT Unregister(int Unit)
			{
			Remove(Unit);
			auto hr2 = UninstallDatabase(Unit);
			if (SUCCEEDED(hr2))
				RestartService();
			return hr2;
		}

		HRESULT Close()
			{
			WinBioCloseSession(sessionHandle);
			sessionHandle = 0;
			return S_OK;
			}

		void SetMine(bool M)
		{
			Mine = M;
			if (!M)
				PRIVATE_POOL_DATABASE_ID = CLSID_NULL;
		}



		void SetType(WINBIO_BIOMETRIC_TYPE i = WINBIO_TYPE_FINGERPRINT)
		{
			TheType = i;
			if (i == WINBIO_TYPE_FACIAL_FEATURES)
				SetAsync(1);
			if (i == WINBIO_TYPE_VOICE)
				SetAsync(1);
		}
		void SetAsync(bool a)
		{
			Async = a;
		}

		void SetDB(CLSID db)
			{
			Mine = true;
			PRIVATE_POOL_DATABASE_ID = db;
			}

		HRESULT Register(size_t idx)
			{
			// Connect to the system pool. 
			if (units.empty())
				Enum();
			if (idx >= units.size())
				return E_INVALIDARG;

			// Database
			hr = InstallDatabase(idx);
			if (FAILED(hr))
				return hr;

			hr = Add(idx);

			if (FAILED(hr))
				return hr;

			// restart the service
			RestartService();
			return hr;
			}

		HRESULT Open(int Unit,HWND hh = 0,UINT mm = 0)
			{
			// Connect to the system pool. 
			if (units.empty())
				Enum();
			std::vector<WINBIO_UNIT_ID> u;
			for (size_t i = 0 ; i < units.size() ; i++)
				{
				if (i == Unit)
					u.push_back(units[i].UnitId);
				}

			if (Async)
			{
				if (Mine)
					hr = WinBioAsyncOpenSession(TheType, WINBIO_POOL_PRIVATE, WINBIO_FLAG_BASIC, u.data(), u.size(), &PRIVATE_POOL_DATABASE_ID, WINBIO_ASYNC_NOTIFY_MESSAGE, hh, mm, 0, 0, FALSE, &sessionHandle);
				else
					hr = WinBioAsyncOpenSession(TheType, WINBIO_POOL_SYSTEM, WINBIO_FLAG_DEFAULT, 0, 0, WINBIO_DB_DEFAULT, WINBIO_ASYNC_NOTIFY_MESSAGE,hh,mm,0,0,FALSE, &sessionHandle);

				if (TheType == WINBIO_TYPE_FACIAL_FEATURES && units.size())
					hr = WinBioMonitorPresence(sessionHandle, units[0].UnitId);
			}
			else
			{
				if (Mine)
					hr = WinBioOpenSession(TheType, WINBIO_POOL_PRIVATE, WINBIO_FLAG_BASIC, u.data(), u.size(), &PRIVATE_POOL_DATABASE_ID, &sessionHandle);
				else
					hr = WinBioOpenSession(TheType, WINBIO_POOL_SYSTEM, WINBIO_FLAG_DEFAULT, 0, 0, WINBIO_DB_DEFAULT, &sessionHandle);
			}
			return hr;
			}

		bool IsAsync() { return Async; }

		HRESULT Locate(WINBIO_UNIT_ID& unitId)
			{
			return WinBioLocateSensor(sessionHandle, &unitId);
			}

		HRESULT Delete(SIZE_T idx,WINBIO_IDENTITY id, WINBIO_BIOMETRIC_SUBTYPE sub)
			{
			if (units.size() <= idx)
				return E_INVALIDARG;
			return WinBioDeleteTemplate(sessionHandle, units[idx].UnitId, &id, sub);
			}

		std::tuple<HRESULT, WINBIO_REJECT_DETAIL, BOOLEAN, WINBIO_IDENTITY>  Enroll(bool PractiseOnly,WINBIO_BIOMETRIC_SUBTYPE sub,size_t idx,std::function<HRESULT(SIZE_T Count,HRESULT hr,WINBIO_REJECT_DETAIL rd)> cb)
			{
			WINBIO_REJECT_DETAIL rejectDetail = 0;
			BOOLEAN isNewTemplate = FALSE;
			WINBIO_IDENTITY identity = {};
			if (units.size() <= idx)
				return std::make_tuple<>(E_INVALIDARG, rejectDetail, isNewTemplate, identity);
			auto u = units[idx];
			hr = WinBioEnrollBegin(sessionHandle, sub, u.UnitId);
			if (FAILED(hr))
				{
				WinBioEnrollDiscard(sessionHandle);
				return std::make_tuple<>(hr, rejectDetail, isNewTemplate, identity);
				}

			for (SIZE_T swipeCount = 1; swipeCount < 20 ; ++swipeCount)
				{
				hr = WinBioEnrollCapture(sessionHandle, &rejectDetail);
				if (FAILED(hr))
					continue;
				hr = cb(swipeCount, hr, rejectDetail);
				if (hr == WINBIO_I_MORE_DATA)
					continue;
				break;
				}

			if (SUCCEEDED(hr))
				{
				if (!PractiseOnly)
					{
					// ENROLL
					hr = WinBioEnrollCommit(sessionHandle, &identity, &isNewTemplate);
					}
				else
					{
					// PRACTICE
					hr = WinBioEnrollDiscard(sessionHandle);
					}
				}
			else
				WinBioEnrollDiscard(sessionHandle);


			return std::make_tuple<>(hr, rejectDetail, isNewTemplate, identity);
			}

		std::tuple<HRESULT,WINBIO_REJECT_DETAIL, WINBIO_BIOMETRIC_SUBTYPE, WINBIO_IDENTITY> Identify(size_t idx)
			{
			WINBIO_REJECT_DETAIL rejectDetail = 0;
			WINBIO_BIOMETRIC_SUBTYPE subFactor = WINBIO_SUBTYPE_NO_INFORMATION;
			WINBIO_IDENTITY identity = {};
			if (units.size() <= idx)
				return std::make_tuple<>(E_INVALIDARG,rejectDetail,subFactor,identity);
			auto u = units[idx];

			
			hr = WinBioIdentify(sessionHandle, &u.UnitId, &identity, &subFactor, &rejectDetail);
			return std::make_tuple<>(hr, rejectDetail, subFactor, identity);
			}

		std::tuple<HRESULT, WINBIO_UNIT_ID,WINBIO_REJECT_DETAIL,BOOL> Verify(WINBIO_IDENTITY& id,WINBIO_BIOMETRIC_SUBTYPE sub)
			{
			WINBIO_UNIT_ID u;
			WINBIO_REJECT_DETAIL rejectDetail = 0;
			BOOLEAN M = false;
			hr = WinBioVerify(sessionHandle, &id,sub,&u,&M,&rejectDetail);
			return std::make_tuple<>(hr,u,rejectDetail,M);
			}

	};

