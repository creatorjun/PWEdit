#include "PasswordChanger.h"
#include <shlwapi.h>
#include <vector>
#include <string>
#include <cctype>
#include <algorithm> // For std::min

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

#define IDC_PASSWORD_EDIT       2001
#define IDC_CONFIRM_EDIT        2002

// --- ntpwedit 암호화 로직 C++ 포팅 ---

// MD4 내부 구현
namespace MD4 {
    struct hash_state {
        UINT64 length;
        UINT32 state[4], curlen;
        BYTE buf[64];
    };

#define F(x, y, z) (z ^ (x & (y ^ z)))
#define G(x, y, z) ((x & y) | (z & (x | y)))
#define H(x, y, z) (x ^ y ^ z)
#define ROLc(x, y) ( (x << y) | (x >> (32 - y)) )
#define RORc(x, y) ( (x >> y) | (x << (32 - y)) ) // RORc 매크로 정의 추가

#define FF(a, b, c, d, x, s) { a += F(b, c, d) + x; a = ROLc(a, s); }
#define GG(a, b, c, d, x, s) { a += G(b, c, d) + x + 0x5a827999UL; a = ROLc(a, s); }
#define HH(a, b, c, d, x, s) { a += H(b, c, d) + x + 0x6ed9eba1UL; a = ROLc(a, s); }

    void compress(hash_state* md, BYTE* buf) {
        UINT32 x[16], a, b, c, d;
        for (int i = 0; i < 16; i++) {
            x[i] = (UINT32)buf[4 * i] | ((UINT32)buf[4 * i + 1] << 8) | ((UINT32)buf[4 * i + 2] << 16) | ((UINT32)buf[4 * i + 3] << 24);
        }
        a = md->state[0]; b = md->state[1]; c = md->state[2]; d = md->state[3];
        FF(a, b, c, d, x[0], 3); FF(d, a, b, c, x[1], 7); FF(c, d, a, b, x[2], 11); FF(b, c, d, a, x[3], 19);
        FF(a, b, c, d, x[4], 3); FF(d, a, b, c, x[5], 7); FF(c, d, a, b, x[6], 11); FF(b, c, d, a, x[7], 19);
        FF(a, b, c, d, x[8], 3); FF(d, a, b, c, x[9], 7); FF(c, d, a, b, x[10], 11); FF(b, c, d, a, x[11], 19);
        FF(a, b, c, d, x[12], 3); FF(d, a, b, c, x[13], 7); FF(c, d, a, b, x[14], 11); FF(b, c, d, a, x[15], 19);
        GG(a, b, c, d, x[0], 3); GG(d, a, b, c, x[4], 5); GG(c, d, a, b, x[8], 9); GG(b, c, d, a, x[12], 13);
        GG(a, b, c, d, x[1], 3); GG(d, a, b, c, x[5], 5); GG(c, d, a, b, x[9], 9); GG(b, c, d, a, x[13], 13);
        GG(a, b, c, d, x[2], 3); GG(d, a, b, c, x[6], 5); GG(c, d, a, b, x[10], 9); GG(b, c, d, a, x[14], 13);
        GG(a, b, c, d, x[3], 3); GG(d, a, b, c, x[7], 5); GG(c, d, a, b, x[11], 9); GG(b, c, d, a, x[15], 13);
        HH(a, b, c, d, x[0], 3); HH(d, a, b, c, x[8], 9); HH(c, d, a, b, x[4], 11); HH(b, c, d, a, x[12], 15);
        HH(a, b, c, d, x[2], 3); HH(d, a, b, c, x[10], 9); HH(c, d, a, b, x[6], 11); HH(b, c, d, a, x[14], 15);
        HH(a, b, c, d, x[1], 3); HH(d, a, b, c, x[9], 9); HH(c, d, a, b, x[5], 11); HH(b, c, d, a, x[13], 15);
        HH(a, b, c, d, x[3], 3); HH(d, a, b, c, x[11], 9); HH(c, d, a, b, x[7], 11); HH(b, c, d, a, x[15], 15);
        md->state[0] += a; md->state[1] += b; md->state[2] += c; md->state[3] += d;
    }
    void init(hash_state* md) {
        md->state[0] = 0x67452301UL; md->state[1] = 0xefcdab89UL;
        md->state[2] = 0x98badcfeUL; md->state[3] = 0x10325476UL;
        md->curlen = 0; md->length = 0;
    }
    void process(hash_state* md, const BYTE* in, DWORD inlen) {
        while (inlen > 0) {
            if (md->curlen == 0 && inlen >= 64) {
                compress(md, (BYTE*)in);
                md->length += 64 * 8; in += 64; inlen -= 64;
            }
            else {
                DWORD n = std::min(inlen, (DWORD)(64 - md->curlen));
                memcpy(md->buf + md->curlen, in, n);
                md->curlen += n; in += n; inlen -= n;
                if (md->curlen == 64) {
                    compress(md, md->buf);
                    md->length += 64 * 8; md->curlen = 0;
                }
            }
        }
    }
    void done(hash_state* md, BYTE* out) {
        md->length += md->curlen * 8;
        md->buf[md->curlen++] = 0x80;
        if (md->curlen > 56) {
            while (md->curlen < 64) md->buf[md->curlen++] = 0;
            compress(md, md->buf); md->curlen = 0;
        }
        while (md->curlen < 56) md->buf[md->curlen++] = 0;
        UINT64 len = md->length;
        memcpy(md->buf + 56, &len, 8);
        compress(md, md->buf);
        for (int i = 0; i < 4; i++) {
            out[4 * i] = (BYTE)(md->state[i] & 0xFF);
            out[4 * i + 1] = (BYTE)((md->state[i] >> 8) & 0xFF);
            out[4 * i + 2] = (BYTE)((md->state[i] >> 16) & 0xFF);
            out[4 * i + 3] = (BYTE)((md->state[i] >> 24) & 0xFF);
        }
    }
}

// DES 내부 구현에 필요한 상수
namespace DES_CONST {
    const ULONG SP1[64] = { 0x1010400,0x0,0x10000,0x1010404,0x1010004,0x10404,0x4,0x10000,0x400,0x1010400,0x1010404,0x400,0x1000404,0x1010004,0x1000000,0x4,0x404,0x1000400,0x1000400,0x10400,0x10400,0x1010000,0x1010000,0x1000404,0x10004,0x1000004,0x1000004,0x10004,0x0,0x404,0x10404,0x1000000,0x10000,0x1010404,0x4,0x1010000,0x1010400,0x1000000,0x1000000,0x400,0x1010004,0x10000,0x10400,0x1000004,0x400,0x4,0x1000404,0x10404,0x1010404,0x10004,0x1010000,0x1000404,0x1000004,0x404,0x10404,0x1010400,0x404,0x1000400,0x1000400,0x0,0x10004,0x10400,0x0,0x1010004 };
    const ULONG SP2[64] = { 0x80108020,0x80008000,0x8000,0x108020,0x100000,0x20,0x80100020,0x80008020,0x80000020,0x80108020,0x80108000,0x80000000,0x80008000,0x100000,0x20,0x80100020,0x108000,0x100020,0x80008020,0x0,0x80000000,0x8000,0x108020,0x80100000,0x100020,0x80000020,0x0,0x108000,0x8020,0x80108000,0x80100000,0x8020,0x0,0x108020,0x80100020,0x100000,0x80008020,0x80100000,0x80108000,0x8000,0x80100000,0x80008000,0x20,0x80108020,0x108020,0x20,0x8000,0x80000000,0x8020,0x80108000,0x100000,0x80000020,0x100020,0x80008020,0x80000020,0x100020,0x108000,0x0,0x80008000,0x8020,0x80000000,0x80100020,0x80108020,0x108000 };
    const ULONG SP3[64] = { 0x208,0x8020200,0x0,0x8020008,0x8000200,0x0,0x20208,0x8000200,0x20008,0x8000008,0x8000008,0x20000,0x8020208,0x20008,0x8020000,0x208,0x8000000,0x8,0x8020200,0x200,0x20200,0x8020000,0x8020008,0x20208,0x8000208,0x20200,0x20000,0x8000208,0x8,0x8020208,0x200,0x8000000,0x8020200,0x8000000,0x20008,0x208,0x20000,0x8020200,0x8000200,0x0,0x200,0x20008,0x8020208,0x8000200,0x8000008,0x200,0x0,0x8020008,0x8000208,0x20000,0x8000000,0x8020208,0x8,0x20208,0x20200,0x8000008,0x8020000,0x8000208,0x208,0x8020000,0x20208,0x8,0x8020008,0x20200 };
    const ULONG SP4[64] = { 0x802001,0x2081,0x2081,0x80,0x802080,0x800081,0x800001,0x2001,0x0,0x802000,0x802000,0x802081,0x81,0x0,0x800080,0x800001,0x1,0x2000,0x800000,0x802001,0x80,0x800000,0x2001,0x2080,0x800081,0x1,0x2080,0x800080,0x2000,0x802080,0x802081,0x81,0x800080,0x800001,0x802000,0x802081,0x81,0x0,0x0,0x802000,0x2080,0x800080,0x800081,0x1,0x802001,0x2081,0x2081,0x80,0x802081,0x81,0x1,0x2000,0x800001,0x2001,0x802080,0x800081,0x2001,0x2080,0x800000,0x802001,0x80,0x800000,0x2000,0x802080 };
    const ULONG SP5[64] = { 0x100,0x2080100,0x2080000,0x42000100,0x80000,0x100,0x40000000,0x2080000,0x40080100,0x80000,0x2000100,0x40080100,0x42000100,0x42080000,0x80100,0x40000000,0x2000000,0x40080000,0x40080000,0x0,0x40000100,0x42080100,0x42080100,0x2000100,0x42080000,0x40000100,0x0,0x42000000,0x2080100,0x2000000,0x42000000,0x80100,0x80000,0x42000100,0x100,0x2000000,0x40000000,0x2080000,0x42000100,0x40080100,0x2000100,0x40000000,0x42080000,0x2080100,0x40080100,0x100,0x2000000,0x42080000,0x42080100,0x80100,0x42000000,0x42080100,0x2080000,0x0,0x40080000,0x42000000,0x80100,0x2000100,0x40000100,0x80000,0x0,0x40080000,0x2080100,0x40000100 };
    const ULONG SP6[64] = { 0x20000010,0x20400000,0x4000,0x20404010,0x20400000,0x10,0x20404010,0x400000,0x20004000,0x404010,0x400000,0x20000010,0x400010,0x20004000,0x20000000,0x4010,0x0,0x400010,0x20004010,0x4000,0x404000,0x20004010,0x10,0x20400010,0x20400010,0x0,0x404010,0x20404000,0x4010,0x404000,0x20404000,0x20000000,0x20004000,0x10,0x20400010,0x404000,0x20404010,0x400000,0x4010,0x20000010,0x400000,0x20004000,0x20000000,0x4010,0x20000010,0x20404010,0x404000,0x20400000,0x404010,0x20404000,0x0,0x20400010,0x10,0x4000,0x20400000,0x404010,0x4000,0x400010,0x20004010,0x0,0x20404000,0x20000000,0x400010,0x20004010 };
    const ULONG SP7[64] = { 0x200000,0x4200002,0x4000802,0x0,0x800,0x4000802,0x200802,0x4200800,0x4200802,0x200000,0x0,0x4000002,0x2,0x4000000,0x4200002,0x802,0x4000800,0x200802,0x200002,0x4000800,0x4000002,0x4200000,0x4200800,0x200002,0x4200000,0x800,0x802,0x4200802,0x200800,0x2,0x4000000,0x200800,0x4000000,0x200800,0x200000,0x4000802,0x4000802,0x4200002,0x4200002,0x2,0x200002,0x4000000,0x4000800,0x200000,0x4200800,0x802,0x200802,0x4200800,0x802,0x4000002,0x4200802,0x4200000,0x200800,0x0,0x2,0x4200802,0x0,0x200802,0x4200000,0x800,0x4000002,0x4000800,0x800,0x200002 };
    const ULONG SP8[64] = { 0x10001040,0x1000,0x40000,0x10041040,0x10000000,0x10001040,0x40,0x10000000,0x40040,0x10040000,0x10041040,0x41000,0x10041000,0x41040,0x1000,0x40,0x10040000,0x10000040,0x10001000,0x1040,0x41000,0x40040,0x10040040,0x10041000,0x1040,0x0,0x0,0x10040040,0x10000040,0x10001000,0x41040,0x40000,0x41040,0x40000,0x10041000,0x1000,0x40,0x10040040,0x1000,0x41040,0x10001000,0x40,0x10000040,0x10040000,0x10040040,0x10000000,0x40000,0x10001040,0x0,0x10041040,0x40040,0x10000040,0x10040000,0x10001000,0x10001040,0x0,0x10041040,0x41000,0x41000,0x1040,0x1040,0x40040,0x10000000,0x10041000 };
    const BYTE key_perm[56] = { 56,48,40,32,24,16,8,0,57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3 };
    const BYTE key_rot[16] = { 1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28 };
    const BYTE key_perm2[48] = { 13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31 };
}

void NtpwCrypto::NtlmHash(const std::wstring& password, BYTE* ntHash) {
    MD4::hash_state md;
    MD4::init(&md);
    MD4::process(&md, (const BYTE*)password.c_str(), (DWORD)password.length() * sizeof(wchar_t));
    MD4::done(&md, ntHash);
}

void NtpwCrypto::str_to_key(const BYTE* str, BYTE* key) {
    key[0] = str[0] >> 1; key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2); key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
    key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4); key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);
    key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6); key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7); key[7] = str[6] & 0x7F;
    for (int i = 0; i < 8; i++) key[i] = (key[i] << 1);
}

void NtpwCrypto::SidToKey(DWORD rid, bool isSecondKey, BYTE* desKey) {
    BYTE s[7];
    if (!isSecondKey) {
        s[0] = (BYTE)(rid & 0xFF); s[1] = (BYTE)((rid >> 8) & 0xFF); s[2] = (BYTE)((rid >> 16) & 0xFF); s[3] = (BYTE)((rid >> 24) & 0xFF);
        s[4] = s[0]; s[5] = s[1]; s[6] = s[2];
    }
    else {
        s[0] = (BYTE)((rid >> 24) & 0xFF); s[1] = (BYTE)(rid & 0xFF); s[2] = (BYTE)((rid >> 8) & 0xFF); s[3] = (BYTE)((rid >> 16) & 0xFF);
        s[4] = s[0]; s[5] = s[1]; s[6] = s[2];
    }
    str_to_key(s, desKey);
}

bool NtpwCrypto::EncryptNtHash(DWORD rid, const BYTE* ntHash, BYTE* encryptedNtHash) {
    BYTE desKey1[8], desKey2[8];
    SidToKey(rid, false, desKey1);
    SidToKey(rid, true, desKey2);

    symmetric_key sk1, sk2;
    des_setup(desKey1, &sk1);
    des_ecb_encrypt(ntHash, encryptedNtHash, &sk1);

    des_setup(desKey2, &sk2);
    des_ecb_encrypt(ntHash + 8, encryptedNtHash + 8, &sk2);

    return true;
}

void NtpwCrypto::des_setup(const BYTE* key, symmetric_key* skey) {
    ULONG kn[32];
    BYTE pc1m[56], pcr[56];

    for (int j = 0; j < 56; j++) {
        ULONG l = DES_CONST::key_perm[j];
        pc1m[j] = (key[l >> 3] & (1 << (7 - (l & 7)))) ? 1 : 0;
    }

    for (int i = 0; i < 16; i++) {
        ULONG m = i << 1, n = m + 1;
        kn[m] = kn[n] = 0;
        for (int j = 0; j < 28; j++) {
            ULONG l = j + DES_CONST::key_rot[i];
            pcr[j] = pc1m[l < 28 ? l : l - 28];
        }
        for (int j = 28; j < 56; j++) {
            ULONG l = j + DES_CONST::key_rot[i];
            pcr[j] = pc1m[l < 56 ? l : l - 28];
        }
        for (int j = 0; j < 24; j++) {
            if (pcr[DES_CONST::key_perm2[j]]) kn[m] |= (1UL << (23 - j));
            if (pcr[DES_CONST::key_perm2[j + 24]]) kn[n] |= (1UL << (23 - j));
        }
    }

    for (int i = 0; i < 16; i++) {
        ULONG raw0 = kn[2 * i], raw1 = kn[2 * i + 1];
        skey->ek[2 * i] = ((raw0 & 0xFC0000) << 6) | ((raw0 & 0xFC0) << 10) | ((raw1 & 0xFC0000) >> 10) | ((raw1 & 0xFC0) >> 6);
        skey->ek[2 * i + 1] = ((raw0 & 0x3F000) << 12) | ((raw0 & 0x3F) << 16) | ((raw1 & 0x3F000) >> 4) | (raw1 & 0x3F);
    }
}

void NtpwCrypto::des_ecb_encrypt(const BYTE* pt, BYTE* ct, symmetric_key* skey) {
    ULONG left, right, work;
    left = (pt[0] << 24) | (pt[1] << 16) | (pt[2] << 8) | pt[3];
    right = (pt[4] << 24) | (pt[5] << 16) | (pt[6] << 8) | pt[7];

    work = ((left >> 4) ^ right) & 0x0f0f0f0f; right ^= work; left ^= (work << 4);
    work = ((left >> 16) ^ right) & 0x0000ffff; right ^= work; left ^= (work << 16);
    work = ((right >> 2) ^ left) & 0x33333333; left ^= work; right ^= (work << 2);
    work = ((right >> 8) ^ left) & 0x00ff00ff; left ^= work; right ^= (work << 8);
    right = ROLc(right, 1);
    work = (left ^ right) & 0xaaaaaaaa; left ^= work; right ^= work;
    left = ROLc(left, 1);

    for (int i = 0; i < 8; i++) {
        work = RORc(right, 4) ^ skey->ek[4 * i];
        left ^= DES_CONST::SP7[work & 0x3f] ^ DES_CONST::SP5[(work >> 8) & 0x3f] ^ DES_CONST::SP3[(work >> 16) & 0x3f] ^ DES_CONST::SP1[(work >> 24) & 0x3f];
        work = right ^ skey->ek[4 * i + 1];
        left ^= DES_CONST::SP8[work & 0x3f] ^ DES_CONST::SP6[(work >> 8) & 0x3f] ^ DES_CONST::SP4[(work >> 16) & 0x3f] ^ DES_CONST::SP2[(work >> 24) & 0x3f];
        work = RORc(left, 4) ^ skey->ek[4 * i + 2];
        right ^= DES_CONST::SP7[work & 0x3f] ^ DES_CONST::SP5[(work >> 8) & 0x3f] ^ DES_CONST::SP3[(work >> 16) & 0x3f] ^ DES_CONST::SP1[(work >> 24) & 0x3f];
        work = left ^ skey->ek[4 * i + 3];
        right ^= DES_CONST::SP8[work & 0x3f] ^ DES_CONST::SP6[(work >> 8) & 0x3f] ^ DES_CONST::SP4[(work >> 16) & 0x3f] ^ DES_CONST::SP2[(work >> 24) & 0x3f];
    }

    left = RORc(left, 1);
    right = RORc(right, 1);
    work = (left ^ right) & 0xaaaaaaaa; left ^= work; right ^= work;
    work = ((left >> 8) ^ right) & 0x00ff00ff; right ^= work; left ^= (work << 8);
    work = ((left >> 2) ^ right) & 0x33333333; right ^= work; left ^= (work << 2);
    work = ((right >> 16) ^ left) & 0x0000ffff; left ^= work; right ^= (work << 16);
    work = ((right >> 4) ^ left) & 0x0f0f0f0f; left ^= work; right ^= (work << 4);

    ct[0] = (BYTE)(right >> 24); ct[1] = (BYTE)(right >> 16); ct[2] = (BYTE)(right >> 8); ct[3] = (BYTE)right;
    ct[4] = (BYTE)(left >> 24); ct[5] = (BYTE)(left >> 16); ct[6] = (BYTE)(left >> 8); ct[7] = (BYTE)left;
}

// --- 기존 클래스 멤버 함수들 (이하 동일) ---

PasswordChanger::PasswordChanger() :m_hParent(nullptr), m_result(false) {}
PasswordChanger::~PasswordChanger() {}

bool PasswordChanger::ShowPasswordChangeDialog(HWND hParent, const std::wstring& windowsPath, const std::wstring& username) {
    m_hParent = hParent; m_windowsPath = windowsPath; m_username = username; m_result = false;
    HWND hDlg = CreateWindow(L"#32770", L"비밀번호 변경", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | DS_MODALFRAME, CW_USEDEFAULT, CW_USEDEFAULT, 320, 180, hParent, nullptr, GetModuleHandle(nullptr), this);
    if (!hDlg) { return false; }
    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");
    HFONT hSmallFont = CreateFont(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"맑은 고딕");
    HWND hPasswordLabel = CreateWindow(L"STATIC", L"새 비밀번호:", WS_VISIBLE | WS_CHILD, 20, 20, 80, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr); SendMessage(hPasswordLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hPasswordEdit = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | WS_TABSTOP, 110, 18, 180, 22, hDlg, (HMENU)IDC_PASSWORD_EDIT, GetModuleHandle(nullptr), nullptr); SendMessage(hPasswordEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hConfirmLabel = CreateWindow(L"STATIC", L"비밀번호 확인:", WS_VISIBLE | WS_CHILD, 20, 50, 80, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr); SendMessage(hConfirmLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hConfirmEdit = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD | WS_TABSTOP, 110, 48, 180, 22, hDlg, (HMENU)IDC_CONFIRM_EDIT, GetModuleHandle(nullptr), nullptr); SendMessage(hConfirmEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hInfoLabel = CreateWindow(L"STATIC", L"※ 빈 칸으로 두면 비밀번호가 제거됩니다.", WS_VISIBLE | WS_CHILD | SS_LEFT, 20, 80, 270, 20, hDlg, nullptr, GetModuleHandle(nullptr), nullptr); SendMessage(hInfoLabel, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    HWND hOKButton = CreateWindow(L"BUTTON", L"변경", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | WS_TABSTOP, 150, 110, 60, 25, hDlg, (HMENU)IDOK, GetModuleHandle(nullptr), nullptr); SendMessage(hOKButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hCancelButton = CreateWindow(L"BUTTON", L"취소", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | WS_TABSTOP, 220, 110, 60, 25, hDlg, (HMENU)IDCANCEL, GetModuleHandle(nullptr), nullptr); SendMessage(hCancelButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetFocus(hPasswordEdit);
    RECT rcParent, rcDlg; GetWindowRect(hParent, &rcParent); GetWindowRect(hDlg, &rcDlg); SetWindowPos(hDlg, nullptr, rcParent.left + (rcParent.right - rcParent.left - (rcDlg.right - rcDlg.left)) / 2, rcParent.top + (rcParent.bottom - rcParent.top - (rcDlg.bottom - rcDlg.top)) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)this); SetWindowLongPtr(hDlg, GWLP_WNDPROC, (LONG_PTR)PasswordDialogProc);
    EnableWindow(hParent, FALSE); MSG msg; while (GetMessage(&msg, nullptr, 0, 0)) { if (!IsDialogMessage(hDlg, &msg)) { TranslateMessage(&msg); DispatchMessage(&msg); } if (!IsWindow(hDlg)) { break; } } EnableWindow(hParent, TRUE); SetFocus(hParent);
    DeleteObject(hFont); DeleteObject(hSmallFont); return m_result;
}

INT_PTR CALLBACK PasswordChanger::PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    PasswordChanger* pThis = (PasswordChanger*)GetWindowLongPtr(hDlg, GWLP_USERDATA);
    if (pThis) { return pThis->HandleDialogMessage(hDlg, message, wParam, lParam); }
    return DefWindowProc(hDlg, message, wParam, lParam);
}

INT_PTR PasswordChanger::HandleDialogMessage(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            wchar_t password[256] = { 0 }, passwordConfirm[256] = { 0 };
            GetDlgItemText(hDlg, IDC_PASSWORD_EDIT, password, 255);
            GetDlgItemText(hDlg, IDC_CONFIRM_EDIT, passwordConfirm, 255);
            if (wcscmp(password, passwordConfirm) != 0) {
                MessageBox(hDlg, L"비밀번호가 일치하지 않습니다.", L"오류", MB_OK | MB_ICONERROR);
                SetFocus(GetDlgItem(hDlg, IDC_PASSWORD_EDIT)); return TRUE;
            }
            m_newPassword = password;
            if (ChangePasswordViaSAM(m_windowsPath, m_username, m_newPassword)) {
                m_result = true; DestroyWindow(hDlg);
            }
            else { MessageBox(hDlg, L"비밀번호 변경에 실패했습니다.", L"오류", MB_OK | MB_ICONERROR); }
        } return TRUE;
        case IDCANCEL: m_result = false; DestroyWindow(hDlg); return TRUE;
        } break;
    case WM_CLOSE: m_result = false; DestroyWindow(hDlg); return TRUE;
    case WM_KEYDOWN: if (wParam == VK_ESCAPE) { m_result = false; DestroyWindow(hDlg); return TRUE; } break;
    }
    return DefWindowProc(hDlg, message, wParam, lParam);
}

bool PasswordChanger::ChangePasswordViaSAM(const std::wstring& windowsPath, const std::wstring& username, const std::wstring& newPassword) {
    std::wstring samPath = windowsPath + L"\\System32\\config\\SAM";
    if (RegLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM", samPath.c_str()) != ERROR_SUCCESS) { return false; }
    HKEY hSAM; bool success = false;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"TempSAM\\SAM\\Domains\\Account", 0, KEY_ALL_ACCESS, &hSAM) == ERROR_SUCCESS) {
        DWORD rid = FindUserRID(hSAM, username);
        if (rid != 0) {
            if (newPassword.empty()) {
                if (ClearUserPassword(hSAM, rid) && UnlockAndEnableAccount(hSAM, rid, false)) { success = true; }
            }
            else {
                if (SetUserPassword(hSAM, rid, newPassword) && UnlockAndEnableAccount(hSAM, rid, true)) { success = true; }
            }
        }
        RegCloseKey(hSAM);
    }
    RegUnLoadKey(HKEY_LOCAL_MACHINE, L"TempSAM"); return success;
}

DWORD PasswordChanger::FindUserRID(HKEY hSAM, const std::wstring& username) {
    HKEY hUsersKey; if (RegOpenKeyEx(hSAM, L"Users\\Names", 0, KEY_READ, &hUsersKey) != ERROR_SUCCESS) { return 0; }
    HKEY hUserKey; DWORD rid = 0;
    if (RegOpenKeyEx(hUsersKey, username.c_str(), 0, KEY_READ, &hUserKey) == ERROR_SUCCESS) {
        DWORD dataSize = sizeof(DWORD), type;
        if (RegQueryValueEx(hUserKey, nullptr, nullptr, &type, (LPBYTE)&rid, &dataSize) == ERROR_SUCCESS) { rid = type; }
        RegCloseKey(hUserKey);
    }
    RegCloseKey(hUsersKey); return rid;
}

bool PasswordChanger::UnlockAndEnableAccount(HKEY hSAM, DWORD rid, bool passwordIsSet) {
    wchar_t ridHex[16]; wsprintf(ridHex, L"Users\\%08X", rid);
    HKEY hUserKey; if (RegOpenKeyEx(hSAM, ridHex, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS) { return false; }
    DWORD dataSize = 0;
    if (RegQueryValueEx(hUserKey, L"F", nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS || dataSize == 0) { RegCloseKey(hUserKey); return false; }
    std::vector<BYTE> userData(dataSize);
    if (RegQueryValueEx(hUserKey, L"F", nullptr, nullptr, userData.data(), &dataSize) != ERROR_SUCCESS) { RegCloseKey(hUserKey); return false; }
    if (dataSize >= 0x3C) {
        DWORD* flags = (DWORD*)&userData[0x38];
        *flags &= ~0x00000001; // UF_ACCOUNTDISABLE
        *flags &= ~0x00000010; // UF_LOCKOUT
        if (passwordIsSet) { *flags &= ~0x00000020; } // UF_PASSWD_NOTREQD 해제
        else { *flags |= 0x00000020; }               // UF_PASSWD_NOTREQD 설정
        if (RegSetValueEx(hUserKey, L"F", 0, REG_BINARY, userData.data(), dataSize) == ERROR_SUCCESS) {
            RegCloseKey(hUserKey); return true;
        }
    }
    RegCloseKey(hUserKey); return false;
}

bool PasswordChanger::ClearUserPassword(HKEY hSAM, DWORD rid) {
    wchar_t ridHex[16]; wsprintf(ridHex, L"Users\\%08X", rid);
    HKEY hUserKey; if (RegOpenKeyEx(hSAM, ridHex, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS) { return false; }
    DWORD dataSize = 0;
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS || dataSize < 0xCC) { RegCloseKey(hUserKey); return false; }
    std::vector<BYTE> vData(dataSize);
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, vData.data(), &dataSize) != ERROR_SUCCESS) { RegCloseKey(hUserKey); return false; }
    *((DWORD*)&vData[0x9C]) = 0; // LM Hash Length
    *((DWORD*)&vData[0xAC]) = 0; // NT Hash Length
    if (RegSetValueEx(hUserKey, L"V", 0, REG_BINARY, vData.data(), dataSize) == ERROR_SUCCESS) {
        RegCloseKey(hUserKey); return true;
    }
    RegCloseKey(hUserKey); return false;
}

bool PasswordChanger::SetUserPassword(HKEY hSAM, DWORD rid, const std::wstring& password) {
    BYTE ntHash[16];
    NtpwCrypto::NtlmHash(password, ntHash);

    BYTE encryptedNtHash[16];
    if (!NtpwCrypto::EncryptNtHash(rid, ntHash, encryptedNtHash)) {
        return false;
    }

    wchar_t ridHex[16]; wsprintf(ridHex, L"Users\\%08X", rid);
    HKEY hUserKey;
    if (RegOpenKeyEx(hSAM, ridHex, 0, KEY_ALL_ACCESS, &hUserKey) != ERROR_SUCCESS) return false;

    DWORD dataSize = 0;
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, nullptr, &dataSize) != ERROR_SUCCESS || dataSize < 0xCC) {
        RegCloseKey(hUserKey);
        return false;
    }
    std::vector<BYTE> vData(dataSize);
    if (RegQueryValueEx(hUserKey, L"V", nullptr, nullptr, vData.data(), &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hUserKey);
        return false;
    }

    DWORD ntHashOffset = *((DWORD*)&vData[0xA8]) + 0xCC;
    if (dataSize < ntHashOffset + 16) {
        RegCloseKey(hUserKey);
        return false;
    }

    memcpy(&vData[ntHashOffset], encryptedNtHash, 16);

    *((DWORD*)&vData[0x9C]) = 0;
    *((DWORD*)&vData[0xAC]) = 16;

    if (RegSetValueEx(hUserKey, L"V", 0, REG_BINARY, vData.data(), dataSize) == ERROR_SUCCESS) {
        RegCloseKey(hUserKey);
        return true;
    }

    RegCloseKey(hUserKey);
    return false;
}