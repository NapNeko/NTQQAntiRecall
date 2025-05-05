#include <string>
// 跨平台兼容个灯
#include <iostream>
#define _WIN_PLATFORM_

#if defined(_WIN_PLATFORM_)
#include <Windows.h>
#elif defined(_LINUX_PLATFORM_)
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#endif

void *GetCallAddress(uint8_t *ptr)
{
	// 读取操作码
	if (ptr[0] != 0xE8)
	{
		printf("Not a call instruction!\n");
		return 0;
	}

	// 读取相对偏移量
	int32_t relativeOffset = *reinterpret_cast<int32_t *>(ptr + 1);

	// 计算函数地址
	uint8_t *callAddress = ptr + 5; // call 指令占 5 个字节
	void *functionAddress = callAddress + relativeOffset;

	return reinterpret_cast<void *>(functionAddress);
}

void *SearchAndFillJump(uint64_t baseAddress, void *targetAddress)
{
	uint8_t jumpInstruction[] = {
		0x49, 0xBB,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x41, 0xFF, 0xE3};

	memcpy(jumpInstruction + 2, &targetAddress, 8);

	// Iterate through memory regions
	uint64_t searchStart = baseAddress - 0x7fffffff;
	uint64_t searchEnd = baseAddress + 0x7fffffff;

#if defined(_WIN_PLATFORM_)
	while (searchStart < searchEnd - sizeof(jumpInstruction))
	{
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery(reinterpret_cast<void *>(searchStart), &mbi, sizeof(mbi)) == 0)
			break;
		if (mbi.State == MEM_COMMIT)
		{
			for (char *addr = static_cast<char *>(mbi.BaseAddress); addr < static_cast<char *>(mbi.BaseAddress) + mbi.RegionSize - 1024 * 5; ++addr)
			{

				bool isFree = true;
				for (int i = 0; i < 1024 * 5; ++i)
				{
					if (addr[i] != 0)
					{
						isFree = false;
						break;
					}
				}
				if (isFree)
				{
					DWORD oldProtect;
					addr += 0x200;
					// printf("addr: %p\n", addr);

					if (!VirtualProtect(addr, sizeof(jumpInstruction), PAGE_EXECUTE_READWRITE, &oldProtect))
						break;
					memcpy(addr, jumpInstruction, sizeof(jumpInstruction));
					if (!VirtualProtect(addr, sizeof(jumpInstruction), PAGE_EXECUTE_READ, &oldProtect))
						break;

					return addr;
				}
			}
		}
		searchStart += mbi.RegionSize;
	}
#elif defined(_LINUX_PLATFORM_)
	// 保证地址对齐
	searchStart &= 0xfffffffffffff000;
	searchStart += 0x1000;
	searchEnd &= 0xfffffffffffff000;

	auto pmap = hak::get_maps();
	do
	{
		auto fpmap = pmap;
		pmap = fpmap->next();
		if (std::min(pmap->start(), searchEnd) - std::max(fpmap->end(), searchStart) > 0x2000) // 搜索一片 0x2000 大小的空区域
		{
			void *addr = mmap(reinterpret_cast<void *>(std::max(fpmap->end(), searchStart)), 0x2000, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			// printf("addr: %p\n", addr);
			if (addr == MAP_FAILED)
			{
				printf("mmap failed\n");
				continue;
			}
			if (reinterpret_cast<uint64_t>(addr) > searchEnd - sizeof(jumpInstruction))
			{
				munmap(addr, 0x2000);
				printf("addr > searchEnd\n");
				continue;
			}
			memcpy(addr, jumpInstruction, sizeof(jumpInstruction));
			if (mprotect(addr, 0x2000, PROT_READ | PROT_EXEC) == -1) // 设置内存 r-w
			{
				munmap(addr, 0x2000);
				printf("mprotect failed\n");
				continue;
			}
			return addr;
		}
	} while (pmap->next() != nullptr);

#endif
	return nullptr;
}

bool Hook(uint8_t *callAddr, void *lpFunction)
{
	uint64_t startAddr = reinterpret_cast<uint64_t>(callAddr) + 5;
	int64_t distance = reinterpret_cast<uint64_t>(lpFunction) - startAddr;
#if defined(_WIN_PLATFORM_)
	// printf("Hooking %p to %p, distance: %lld\n", callAddr, lpFunction, distance);

	DWORD oldProtect;
	DWORD reProtect;
	if (!VirtualProtect(callAddr, 10, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		printf("VirtualProtect failed\n");
		return false;
	}
	if (distance < INT32_MIN || distance > INT32_MAX)
	{
		void *new_ret = SearchAndFillJump(startAddr, lpFunction);
		if (new_ret == nullptr)
		{
			printf("Can't find a place to jump\n");
			return false;
		}
		distance = reinterpret_cast<uint64_t>(new_ret) - startAddr;
		// printf("new_ret: %p, new_distance: %lld\n", new_ret, distance);
	}
	// 直接进行小跳转
	memcpy(callAddr + 1, reinterpret_cast<int32_t *>(&distance), 4); // 修改 call 地址
	if (!VirtualProtect(callAddr, 10, oldProtect, &reProtect))		 // 恢复原来的内存保护属性
	{
		std::cout << GetLastError()<<"/"<<callAddr<<"/"<<oldProtect<<"/"<<reProtect;
		printf("VirtualProtect failed\n");
		return false;
	}
	return true;
#elif defined(_LINUX_PLATFORM_)
	// printf("Hooking %p to %p, distance: %ld\n", callAddr, lpFunction, distance);

	auto get_page_addr = [](void *addr) -> void *
	{
		return (void *)((uintptr_t)addr & ~(getpagesize() - 1));
	};

	if (mprotect(get_page_addr(callAddr), 2 * getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) // 设置内存可写 两倍 pagesize 防止处于页边界
	{
		printf("mprotect failed\n");
		return false;
	}
	if (distance < INT32_MIN || distance > INT32_MAX)
	{
		void *new_ret = SearchAndFillJump(startAddr, lpFunction);
		if (new_ret == nullptr)
		{
			printf("Can't find a place to jump\n");
			return false;
		}
		distance = reinterpret_cast<uint64_t>(new_ret) - startAddr;
		// printf("new_ret: %p, new_distance: %ld\n", new_ret, distance);
	}

	memcpy(callAddr + 1, reinterpret_cast<int32_t *>(&distance), 4);					   // 修改 call 地址
	if (mprotect(get_page_addr(callAddr), 2 * getpagesize(), PROT_READ | PROT_EXEC) == -1) // 还原内存保护属性
	{
		printf("mprotect failed\n");
		return false;
	}
	return true;
#endif
}