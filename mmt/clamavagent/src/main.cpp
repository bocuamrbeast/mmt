#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdio>  // popen, pclose

using namespace std;

const int PORT = 9001;
const int BUFFER_SIZE = 4096;

// Hàm quét virus bằng clamscan
string scan_file(const string& filepath) {
    string command = "clamscan " + filepath + " --no-summary";
    vector<char> buffer(128);
    string result;

    FILE* pipe = _popen(command.c_str(), "r");

    if (!pipe) return "ERROR";

    while (fgets(buffer.data(), buffer.size(), pipe)) {
        result += buffer.data();
    }

    _pclose(pipe);

    return (result.find("OK") != string::npos) ? "OK" : "INFECTED";
}

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "Failed to initialize Winsock.\n";
        return 1;
    }

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        cerr << "Failed to create socket.\n";
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Bind failed.\n";
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    listen(server_fd, 5);
    cout << "[ClamAVAgent] Listening on port " << PORT << "...\n";

    while (true) {
        SOCKET client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            cerr << "Accept failed.\n";
            continue;
        }

        // Nhận tên file (256 byte)
        char name_buf[256] = {0};
        recv(client_fd, name_buf, sizeof(name_buf), 0);
        string filename(name_buf);

        string temp_path = ".\\tmp_" + filename;

        // Nhận kích thước file
        int file_size = 0;
        recv(client_fd, (char*)&file_size, sizeof(file_size), 0);

        // Nhận nội dung file và ghi ra tạm thời
        ofstream ofs(temp_path, ios::binary);
        int received = 0;
        vector<char> buffer(BUFFER_SIZE);

        while (received < file_size) {
            int bytes = recv(client_fd, buffer.data(), buffer.size(), 0);
            if (bytes <= 0) break;
            ofs.write(buffer.data(), bytes);
            received += bytes;
        }
        ofs.close();

        cout << "[Received] File: " << filename << ", Size: " << file_size << " bytes\n";

        // Gọi ClamAV để scan
        string result = scan_file(temp_path);
        cout << "[Scan Result] " << filename << ": " << result << "\n";

        // Gửi kết quả về client
        send(client_fd, result.c_str(), result.length(), 0);

        closesocket(client_fd);

        remove(temp_path.c_str());
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
