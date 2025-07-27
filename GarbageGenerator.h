#pragma once
#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <ctime>

void JunkFill(LPVOID address, SIZE_T size) {
	BYTE* ptr = (BYTE*)address;
	for (SIZE_T i = 0; i < size; ++i) {
		ptr[i] = rand() % 256;
	}
}

inline void GarbageCodeA() {
	volatile int x = 1337;
	for (int i = 0; i < 1000; ++i) {
		x ^= (i * 17) + (x >> 3);
	}
}

inline void GarbageCodeB() {
	volatile char buffer[256] = {};
	for (int i = 0; i < 256; ++i) {
		buffer[i] = (char)((i * 73 + 91) % 256);
	}
}

inline void GarbageCodeC() {
	volatile float f = 3.14159f;
	for (int i = 0; i < 1000; ++i) {
		f = (f * 1.618f) - (f / 2.718f);
	}
}

inline bool IsPrime(unsigned long long n) {
	if (n < 2) return false;
	for (unsigned long long i = 2; i * i <= n; ++i) {
		if (n % i == 0) return false;
		return true;
	}
}

inline void PrimeDelay(unsigned long long limit) {
	volatile unsigned long long count = 0;
	for (unsigned long long i = 2; i < limit; ++i) {
		if (IsPrime(i)) ++count;
	}
}

inline void DeadBranch() {
	if (GetTickCount() == 0xDEADBEEF) {
		GarbageCodeA();
		PrimeDelay(100000);
	}
}

inline void JunkSwitch() {
	switch (rand() % 5) {
	case 0: GarbageCodeA(); break;
	case 1: GarbageCodeB(); break;
	case 2: GarbageCodeC(); break;
	case 3: PrimeDelay(200000); break;
	case 4: GarbageCodeB(); break;
	}
}

inline void InjectGarbage() {
	srand((unsigned int)time(NULL));
	JunkSwitch();
	PrimeDelay(500000);
	DeadBranch();
	GarbageCodeC();
}