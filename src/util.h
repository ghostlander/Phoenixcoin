// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef UTIL_H
#define UTIL_H

#include <map>
#include <string>
#include <algorithm>
#include <vector>
#include <cstring> // for memcpy

#include <boost/date_time/gregorian/gregorian_types.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/thread.hpp>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include "compat.h"
#include "uint256.h"
#include "serialize.h"

static const int64 COIN = 100000000;
static const int64 CENT = 1000000;

#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

// This is needed because the foreach macro can't get over the comma in pair<t1, t2>
#define PAIRTYPE(t1, t2)    std::pair<t1, t2>

// Align by increasing pointer, must have extra space at end of buffer
template <size_t nBytes, typename T>
T* alignup(T* p)
{
    union
    {
        T* ptr;
        size_t n;
    } u;
    u.ptr = p;
    u.n = (u.n + (nBytes-1)) & ~(nBytes-1);
    return u.ptr;
}

#ifdef WINDOWS
#define MSG_NOSIGNAL        0
#define MSG_DONTWAIT        0

#ifndef S_IRUSR
#define S_IRUSR             0400
#define S_IWUSR             0200
#endif
#else
#define MAX_PATH            1024
inline void Sleep(int64 n)
{
    /*Boost has a year 2038 problem— if the request sleep time is past epoch+2^31 seconds the sleep returns instantly.
      So we clamp our sleeps here to 10 years and hope that boost is fixed by 2028.*/
    boost::thread::sleep(boost::get_system_time() + boost::posix_time::milliseconds(n>315576000000LL?315576000000LL:n));
}
#endif


extern std::map<std::string, std::string> mapArgs;
extern std::map<std::string, std::vector<std::string> > mapMultiArgs;
extern bool fDebug;
extern bool fDebugNet;
extern bool fPrintToConsole;
extern bool fPrintToDebugger;
extern bool fRequestShutdown;
extern bool fShutdown;
extern bool fDaemon;
extern bool fServer;
extern bool fCommandLine;
extern std::string strMiscWarning;
extern bool fTestNet;
extern bool fNoListen;
extern bool fLogTimestamps;
extern bool fReopenDebugLog;

extern bool fNeoScrypt;
extern uint nNeoScryptOptions;

extern int64 nPeersOffset;

void RandAddSeed();
void RandAddSeedPerfmon();

void LogException(std::exception* pex, const char* pszThread);
void PrintException(std::exception* pex, const char* pszThread);
void PrintExceptionContinue(std::exception* pex, const char* pszThread);
void ParseString(const std::string& str, char c, std::vector<std::string>& v);
std::string FormatMoney(int64 n, bool fPlus=false);
bool ParseMoney(const std::string& str, int64& nRet);
bool ParseMoney(const char* pszIn, int64& nRet);
std::vector<unsigned char> ParseHex(const char* psz);
std::vector<unsigned char> ParseHex(const std::string& str);
bool IsHex(const std::string& str);
std::vector<unsigned char> DecodeBase64(const char* p, bool* pfInvalid = NULL);
std::string DecodeBase64(const std::string& str);
std::string EncodeBase64(const unsigned char* pch, size_t len);
std::string EncodeBase64(const std::string& str);
std::vector<unsigned char> DecodeBase32(const char* p, bool* pfInvalid = NULL);
std::string DecodeBase32(const std::string& str);
std::string EncodeBase32(const unsigned char* pch, size_t len);
std::string EncodeBase32(const std::string& str);
void ParseParameters(int argc, const char*const argv[]);
bool WildcardMatch(const char* psz, const char* mask);
bool WildcardMatch(const std::string& str, const std::string& mask);
int FileCommit(FILE *fileout);
int GetFilesize(FILE* file);
bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest);
boost::filesystem::path GetDefaultDataDir();
const boost::filesystem::path &GetDataDir(bool fNetSpecific = true);
boost::filesystem::path GetConfigFile();
boost::filesystem::path GetPidFile();
void CreatePidFile(const boost::filesystem::path &path, pid_t pid);
void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet, std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);
void ShrinkDebugFile();
int GetRandInt(int nMax);
uint64 GetRand(uint64 nMax);
uint256 GetRandHash();
int64 GetTime();
void SetMockTime(int64 nMockTimeIn);
int64 GetAdjustedTime();
std::string FormatFullVersion();
std::string FormatSubVersion(const std::string& name, int nClientVersion, const std::vector<std::string>& comments);
void runCommand(std::string strCommand);


/* This GNU C extension enables the compiler to check the format string against the parameters provided.
 * X is the number of the "format string" parameter, and Y is the number of the first variadic parameter.
 * Parameters count from 1.
 */
#ifdef __GNUC__
#define ATTR_WARN_PRINTF(X,Y) __attribute__((format(printf,X,Y)))
#else
#define ATTR_WARN_PRINTF(X,Y)
#endif

int ATTR_WARN_PRINTF(1,2) OutputDebugStringF(const char *pszFormat, ...);

/*
  Rationale for the real_strprintf / strprintf construction:
    It is not allowed to use va_start with a pass-by-reference argument.
    (C++ standard, 18.7, paragraph 3). Use a dummy argument to work around this, and use a
    macro to keep similar semantics.
*/

/** Overload strprintf for char*, so that GCC format type warnings can be given */
std::string ATTR_WARN_PRINTF(1,3) real_strprintf(const char *format, int dummy, ...);
/** Overload strprintf for std::string, to be able to use it with _ (translation).
 * This will not support GCC format type warnings (-Wformat) so be careful.
 */
std::string real_strprintf(const std::string &format, int dummy, ...);
#define strprintf(format, ...) real_strprintf(format, 0, __VA_ARGS__)
std::string vstrprintf(const char *format, va_list ap);

bool ATTR_WARN_PRINTF(1,2) error(const char *format, ...);

/* Redefine printf so that it directs output to debug.log
 *
 * Do this *after* defining the other printf-like functions, because otherwise the
 * __attribute__((format(printf,X,Y))) gets expanded to __attribute__((format(OutputDebugStringF,X,Y)))
 * which confuses gcc.
 */
#define printf OutputDebugStringF


inline std::string i64tostr(int64 n) {
    return(strprintf("%" PRI64d "", n));
}

inline std::string itostr(int n) {
    return(strprintf("%d", n));
}

inline int64 atoi64(const char* psz)
{
#ifdef _MSC_VER
    return _atoi64(psz);
#else
    return strtoll(psz, NULL, 10);
#endif
}

inline int64 atoi64(const std::string& str)
{
#ifdef _MSC_VER
    return _atoi64(str.c_str());
#else
    return strtoll(str.c_str(), NULL, 10);
#endif
}

inline int atoi(const std::string& str)
{
    return atoi(str.c_str());
}

inline int roundint(double d)
{
    return (int)(d > 0 ? d + 0.5 : d - 0.5);
}

inline int64 roundint64(double d)
{
    return (int64)(d > 0 ? d + 0.5 : d - 0.5);
}

inline int64 abs64(int64 n)
{
    return (n >= 0 ? n : -n);
}

template<typename T>
std::string HexStr(const T itbegin, const T itend, bool fSpaces=false)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        if(fSpaces && it != itbegin)
            rv.push_back(' ');
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return rv;
}

inline std::string HexStr(const std::vector<unsigned char>& vch, bool fSpaces=false)
{
    return HexStr(vch.begin(), vch.end(), fSpaces);
}

template<typename T>
void PrintHex(const T pbegin, const T pend, const char* pszFormat="%s", bool fSpaces=true)
{
    printf(pszFormat, HexStr(pbegin, pend, fSpaces).c_str());
}

inline void PrintHex(const std::vector<unsigned char>& vch, const char* pszFormat="%s", bool fSpaces=true)
{
    printf(pszFormat, HexStr(vch, fSpaces).c_str());
}

/* Returns system time in microseconds since the Epoch */
inline int64 GetTimeMicros() {
    uint64 nTime = 0;

#ifdef WINDOWS
    /* Number of 100ns intervals from 12:00 01-Jan-1601 to 00:00 01-Jan-1970 */
    const uint64 EPOCH = 116444736000000000ULL;

    FILETIME nFileTime;

    GetSystemTimeAsFileTime(&nFileTime);
    nTime |= (uint64)nFileTime.dwHighDateTime;
    nTime <<= 32;
    nTime |= (uint64)nFileTime.dwLowDateTime;
    nTime -= EPOCH;
    nTime /= 10;
#else
    timeval t;
    gettimeofday(&t, NULL);
    nTime = (((uint64)t.tv_sec) * 1000000) + (uint64)t.tv_usec;
#endif

    return((int64)nTime);
}

inline int64 GetTimeMillis() {
    return(GetTimeMicros() / 1000);
}

inline std::string DateTimeStrFormat(const char* pszFormat, int64 nTime)
{
    time_t n = nTime;
    struct tm* ptmTime = gmtime(&n);
    char pszTime[200];
    strftime(pszTime, sizeof(pszTime), pszFormat, ptmTime);
    return pszTime;
}

static const std::string strTimestampFormat = "%d-%b-%Y %H:%M:%S UTC";
inline std::string DateTimeStrFormat(int64 nTime) {
    return(DateTimeStrFormat(strTimestampFormat.c_str(), nTime));
}

template<typename T>
void skipspaces(T& it)
{
    while (isspace(*it))
        ++it;
}

inline bool IsSwitchChar(char c)
{
#ifdef WINDOWS
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}

/**
 * Return string argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. "1")
 * @return command-line argument or default value
 */
std::string GetArg(const std::string& strArg, const std::string& strDefault);

/**
 * Return integer argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (e.g. 1)
 * @return command-line argument (0 if invalid number) or default value
 */
int64 GetArg(const std::string& strArg, int64 nDefault);

/**
 * Return boolean argument or default value
 *
 * @param strArg Argument to get (e.g. "-foo")
 * @param default (true or false)
 * @return command-line argument or default value
 */
bool GetBoolArg(const std::string& strArg, bool fDefault=false);

/**
 * Set an argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param strValue Value (e.g. "1")
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetArg(const std::string& strArg, const std::string& strValue);

/**
 * Set a boolean argument if it doesn't already have a value
 *
 * @param strArg Argument to set (e.g. "-foo")
 * @param fValue Value (e.g. false)
 * @return true if argument gets set, false if it already had a value
 */
bool SoftSetBoolArg(const std::string& strArg, bool fValue);









template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

class CHashWriter
{
private:
    EVP_MD_CTX* ctx;  // EVP message digest context

public:
    int nType;
    int nVersion;

    void Init() {
        ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    }

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
        Init();
    }

    ~CHashWriter() {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }

    CHashWriter& write(const char *pch, size_t size) {
        EVP_DigestUpdate(ctx, pch, size);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash() {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int length = 0;

        EVP_DigestFinal_ex(ctx, hash, &length);

        // Re-initialize context to avoid reuse issues
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

        uint256 hash1;
        memcpy(&hash1, hash, sizeof(hash1));

        // Double SHA256 as in original
        uint256 hash2;
        EVP_MD_CTX* ctx2 = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx2, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx2, &hash1, sizeof(hash1));
        EVP_DigestFinal_ex(ctx2, (unsigned char*)&hash2, &length);
        EVP_MD_CTX_free(ctx2);

        return hash2;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};

// Hash function for two ranges
template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    const unsigned char* p1ptr = (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]);
    size_t p1len = (p1end - p1begin) * sizeof(p1begin[0]);
    EVP_DigestUpdate(ctx, p1ptr, p1len);

    const unsigned char* p2ptr = (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]);
    size_t p2len = (p2end - p2begin) * sizeof(p2begin[0]);
    EVP_DigestUpdate(ctx, p2ptr, p2len);

    unsigned int length = 0;
    EVP_DigestFinal_ex(ctx, (unsigned char*)&hash1, &length);
    EVP_MD_CTX_free(ctx);

    // Double SHA256
    uint256 hash2;
    EVP_MD_CTX* ctx2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx2, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx2, &hash1, sizeof(hash1));
    EVP_DigestFinal_ex(ctx2, (unsigned char*)&hash2, &length);
    EVP_MD_CTX_free(ctx2);

    return hash2;
}

// Hash function for three ranges
template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    const unsigned char* p1ptr = (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]);
    size_t p1len = (p1end - p1begin) * sizeof(p1begin[0]);
    EVP_DigestUpdate(ctx, p1ptr, p1len);

    const unsigned char* p2ptr = (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]);
    size_t p2len = (p2end - p2begin) * sizeof(p2begin[0]);
    EVP_DigestUpdate(ctx, p2ptr, p2len);

    const unsigned char* p3ptr = (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]);
    size_t p3len = (p3end - p3begin) * sizeof(p3begin[0]);
    EVP_DigestUpdate(ctx, p3ptr, p3len);

    unsigned int length = 0;
    EVP_DigestFinal_ex(ctx, (unsigned char*)&hash1, &length);
    EVP_MD_CTX_free(ctx);

    // Double SHA256
    uint256 hash2;
    EVP_MD_CTX* ctx2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx2, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx2, &hash1, sizeof(hash1));
    EVP_DigestFinal_ex(ctx2, (unsigned char*)&hash2, &length);
    EVP_MD_CTX_free(ctx2);

    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    uint256 hash1;
    SHA256(&vch[0], vch.size(), (unsigned char*)&hash1);

    uint160 hash2;
    unsigned int len = 0;

    // Initialize EVP_MD_CTX
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        // handle error
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    // Initialize digest context for RIPEMD160
    if (1 != EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL))
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Perform digest
    if (1 != EVP_DigestUpdate(ctx, &hash1, sizeof(hash1)))
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Finalize digest
    if (1 != EVP_DigestFinal_ex(ctx, (unsigned char*)&hash2, &len))
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);
    return hash2;
}


/** Median filter over a stream of values.
 * Returns the median of the last N numbers
 */
template <typename T> class CMedianFilter
{
private:
    std::vector<T> vValues;
    std::vector<T> vSorted;
    unsigned int nSize;
public:
    CMedianFilter(unsigned int size, T initial_value):
        nSize(size)
    {
        vValues.reserve(size);
        vValues.push_back(initial_value);
        vSorted = vValues;
    }

    void input(T value)
    {
        if(vValues.size() == nSize)
        {
            vValues.erase(vValues.begin());
        }
        vValues.push_back(value);

        vSorted.resize(vValues.size());
        std::copy(vValues.begin(), vValues.end(), vSorted.begin());
        std::sort(vSorted.begin(), vSorted.end());
    }

    T median() const
    {
        int size = vSorted.size();
        assert(size>0);
        if(size & 1) // Odd number of elements
        {
            return vSorted[size/2];
        }
        else // Even number of elements
        {
            return (vSorted[size/2-1] + vSorted[size/2]) / 2;
        }
    }

    int size() const
    {
        return vValues.size();
    }

    std::vector<T> sorted () const
    {
        return vSorted;
    }
};

#if (BOOST_VERSION > 106501)
bool NewThread(void(*pfn)(void*), void* parg);
#endif






// Note: It turns out we might have been able to use boost::thread
// by using TerminateThread(boost::thread.native_handle(), 0);
#ifdef WINDOWS

#if (BOOST_VERSION <= 106501)
inline HANDLE NewThread(void(*pfn)(void*), void* parg, bool fWantHandle=false)
{
    DWORD nUnused = 0;
    HANDLE hthread =
        NewThread(
            NULL,                        // default security
            0,                           // inherit stack size from parent
            (LPTHREAD_START_ROUTINE)pfn, // function pointer
            parg,                        // argument
            0,                           // creation option, start immediately
            &nUnused);                   // thread identifier
    if (hthread == NULL)
    {
        printf("Error: CreateThread() returned %d\n", GetLastError());
        return (HANDLE)0;
    }
    if (!fWantHandle)
    {
        CloseHandle(hthread);
        return (HANDLE)-1;
    }
    return hthread;
}
#endif

inline void SetThreadPriority(int nPriority)
{
    SetThreadPriority(GetCurrentThread(), nPriority);
}
#else
#if (BOOST_VERSION <= 106501)
inline pthread_t NewThread(void(*pfn)(void*), void* parg, bool fWantHandle=false)
{
    pthread_t hthread = 0;
    int ret = pthread_create(&hthread, NULL, (void*(*)(void*))pfn, parg);
    if (ret != 0)
    {
        printf("Error: pthread_create() returned %d\n", ret);
        return (pthread_t)0;
    }
    if (!fWantHandle)
    {
        pthread_detach(hthread);
        return (pthread_t)-1;
    }
    return hthread;
}
#endif

#define THREAD_PRIORITY_LOWEST          PRIO_MAX
#define THREAD_PRIORITY_BELOW_NORMAL    2
#define THREAD_PRIORITY_NORMAL          0
#define THREAD_PRIORITY_ABOVE_NORMAL    0

inline void SetThreadPriority(int nPriority)
{
    // It's unclear if it's even possible to change thread priorities on Linux,
    // but we really and truly need it for the generation threads.
#ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
#else
    setpriority(PRIO_PROCESS, 0, nPriority);
#endif
}

inline void ExitThread(size_t nExitCode)
{
    pthread_exit((void*)nExitCode);
}
#endif

void RenameThread(const char* name);

inline uint32_t ByteReverse(uint32_t value)
{
    value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
    return (value<<16) | (value>>16);
}

#endif /* UTIL_H */
