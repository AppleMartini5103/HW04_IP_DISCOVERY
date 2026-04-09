#pragma once

#include <cstdint>
#include <string>

// 특정 호스트의 특정 포트에 TCP 연결 시도
// 반환: true = 포트 열림, false = 포트 닫힘/타임아웃
bool port_check_tcp(const std::string& ip, uint16_t port, int timeout_ms);
