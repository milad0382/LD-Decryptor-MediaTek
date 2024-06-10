#ifndef MISC_H
#define MISC_H
#include <QString>
#include <QDir>
#include <vector>

namespace core {
class Conversion
{
public:
    Conversion() {}
    ~Conversion() {}
};
class Checksum
{
public:
    enum Type {NONE, CRC16, CRC16_SPRD, CRC32};
    Checksum(Type type = NONE);
    ~Checksum() {}
    void addData(void *data, int len);
    static int64_t  verifyData(char *src, char *dist, size_t len);
    static QByteArray swapMtkNv(QByteArray);
protected:
    uint16_t crc16Table[256];
    uint16_t crc16Instances;
    uint32_t crc32Table[256];
    uint32_t crc32Instances;
    Type     m_type;
    bool     m_zero {true};

};
class Crypto
{
public:
    Crypto() {}
    ~Crypto() {}
    static void cryptAES_CFB128_Data(QByteArray*, const QByteArray, bool = true);
    static QByteArray cryptMtk(const QByteArray &, const QByteArray &, const QByteArray &, bool = true);
    static QByteArray cryptMtkNv(const QByteArray, bool = 1);

protected:
    enum Type {INVALID, PUBLIC, PRIVATE};
    static Type classifyKeyType(const QByteArray&);
    static QString getSslError(QString);
};
}

#endif // MISC_H
