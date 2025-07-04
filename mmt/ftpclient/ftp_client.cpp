#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <filesystem>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

const int CLAMAV_PORT = 9001;
const string CLAMAV_IP = "127.0.0.1";
const int BUFFER_SIZE = 4096;

// Gửi file tới ClamAV để quét virus
string scan_with_clamav(const string& filename) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        cerr << "Socket creation failed.\n";
        return "ERROR";
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(CLAMAV_PORT);
    inet_pton(AF_INET, CLAMAV_IP.c_str(), &server.sin_addr);

    if (connect(sock, (sockaddr*)&server, sizeof(server)) < 0) {
        cerr << "Connect to ClamAV failed.\n";
        closesocket(sock);
        return "ERROR";
    }

    // Gửi tên file
    string name = filesystem::path(filename).filename().string();
    send(sock, name.c_str(), 256, 0);

    // Gửi kích thước
    ifstream file(filename, ios::binary | ios::ate);
    int64_t size = file.tellg();
    file.seekg(0);
    send(sock, (char*)&size, sizeof(size), 0);

    // Gửi nội dung file
    vector<char> buffer(BUFFER_SIZE);
    int64_t sent = 0;
    while (file) {
        file.read(buffer.data(), buffer.size());
        int bytes = file.gcount();
        if (bytes > 0)
            send(sock, buffer.data(), bytes, 0);
    }
    file.close();

    // Nhận kết quả
    char result[32] = {0};
    recv(sock, result, sizeof(result), 0);
    closesocket(sock);

    return string(result);
}

// Hàm upload file tới FTP Server bằng lệnh hệ thống ftp
bool upload_to_ftp(const string& filename, const string& ftp_ip) {
    string ftp_user, ftp_pass;
    cout << "FTP username: "; cin >> ftp_user;
    cout << "FTP password: "; cin >> ftp_pass;

    // Tạo script path rõ ràng
    string script_path = "ftp_upload.txt";
    string log_path = "ftp_log.txt";

    // Ghi nội dung vào file bằng mode binary để đảm bảo CRLF
    ofstream script(script_path, ios::binary);
    script << "open " << ftp_ip << "\r\n";
    script << "user " << ftp_user << " " << ftp_pass << "\r\n";
    script << "binary\r\n";
    script << "put \"" << filename << "\"\r\n";
    script << "bye\r\n";
    script.close();  // Đảm bảo đóng file trước khi gọi system()

    // Gọi lệnh ftp và redirect log để debug
    string cmd = "ftp -s:" + script_path + " > " + log_path;
    int result = system(cmd.c_str());

    // Đọc log để kiểm tra lỗi
    ifstream log(log_path);
    string line;
    while (getline(log, line)) {
        if (line.find("530") != string::npos || line.find("Login failed") != string::npos) {
            cerr << "[!] FTP login failed:\n" << line << endl;
            return false;
        }
    }

    return result;
}


int main() {
    // Khởi tạo Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    string ftp_ip;
    cout << "Enter FTP server IP: ";
    cin >> ftp_ip;

    string command;
    while (true) {
        cout << "ftp> ";
        cin >> command;

        if (command == "put") {
            string filename;
            cin >> filename;

            cout << "[+] Scanning file with ClamAV...\n";
            string result = scan_with_clamav(filename);

            if (result == "OK") {
                cout << "[+] File is clean. Uploading...\n";
                if (upload_to_ftp(filename, ftp_ip)) {
                    cout << "[v] Uploaded successfully.\n";
                } else {
                    cout << "[!] FTP upload failed.\n";
                }
            } else {
                cout << "[!] File is INFECTED. Upload canceled.\n";
            }
        }
        else if (command == "quit" || command == "bye") {
            break;
        }
        else {
            cout << "Unsupported command.\n";
        }
    }

    WSACleanup();
    return 0;
}
