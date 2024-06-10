#include "Misc.h"
#include <QStringList>
#include <QFile>
#include <QCryptographicHash>
#include <Windows.h>
#include <QByteArray>
#include <QByteArrayList>
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include <QStringList>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDebug>
#include <memory>
using core::Conversion;
using std::string;
using std::vector;
using core::Checksum;
Checksum::Checksum(Type type):
    m_type(type)
{
    m_zero = true;

    switch(m_type)
    {
    case CRC16:
    case CRC16_SPRD:
    {
        uint16_t crc, c;
        for (int i=0; i<256; i++) {
            crc=0; c=i;
            for (int j=0; j<8; j++) {
                crc = (crc^c)&1? (crc>>1)^0xa001 : crc>>1;
                c = c>>1;
            }
            crc16Table[i] = crc;
        }
    } break;
    case CRC32:
    {
        uint32_t crc;
        for (int i = 0; i < 256; i++)
        {
            crc = i;
            for (int j = 0; j < 8; j++)
                crc = crc & 1? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
            crc32Table[i] = crc;
        }
    } break;
    case NONE:
    {
        m_zero = true;
    } break;
    }
}
QByteArray Checksum::swapMtkNv(QByteArray data)
{
#define ABCDEF(x) ((x >= 'A' && x <= 'F')? \
    (char(x |= (0x22)) - 'a' + 0xa) : x - '0')

    QByteArray tmp = {0};
    for (int i = 0; i < 8; i++)
    {
        char num = {static_cast<char>(data[i * 2 + 1])};
        char val = ABCDEF(num);
        val = ((val << 4) & 0xf0u);
        char str = {static_cast<char>(data[i * 2])};
        val += ABCDEF(str);
        tmp.push_back(val);
    }

    tmp[7] = tmp.data()[7] |= 0xf0;
    tmp[8] = 0xff;
    tmp[9] = 0xff;

    return tmp;
}
#ifndef S_SWAP
#define S_SWAP(a,b) do { uint8_t t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
#endif
#define BLKSIZE 4096
void core::Crypto::cryptAES_CFB128_Data(QByteArray *data, const QByteArray key, bool encrypt)
{
    AES_KEY aesKey;

    unsigned char buff[16];

    if (encrypt)
        AES_set_encrypt_key((const unsigned char*)key.constData(), 128, &aesKey);
    else
        AES_set_decrypt_key((const unsigned char*)key.constData(), 128, &aesKey);

    QByteArray tmp = *data;
    int     offset = 0,
            len = tmp.length();

    data->clear();
    while (len)
    {

        int buflen = std::min(len, 16);
        memset(buff, 0, 16);
        AES_ecb_encrypt((unsigned char*) tmp.mid(offset, buflen).constData(), buff, &aesKey, (const int)encrypt);

        data->append((char*)buff, buflen);
        len -= buflen;
        offset += buflen;
    }
}
QByteArray core::Crypto::cryptMtk(const QByteArray &key, const QByteArray &ivec, const QByteArray &data, bool encrypt)
{
    AES_KEY AesKey;

    int ret = -1;
    if(!encrypt)
        ret = AES_set_decrypt_key(reinterpret_cast<const uchar *>(key.constData()), 128, &AesKey);
    else
        ret = AES_set_encrypt_key(reinterpret_cast<const uchar *>(key.constData()), 128, &AesKey);

    if(ret < 0) return "";

    uchar iv[AES_BLOCK_SIZE+1] = {};
    for (int i = 0; i < ivec.size(); i++)
        memcpy(&iv[i], &ivec.data()[i], sizeof(uchar));

    int len = data.length();
    if(len % AES_BLOCK_SIZE != 0)
        len = (len/AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    QByteArray data2(data);
    data2.append(len - data2.length(), '\0');

    std::shared_ptr<uchar> out(new uchar[len+1], [](uchar *p)
    {
        delete []p;
    });

    if(!encrypt)
        AES_cbc_encrypt(reinterpret_cast<const uchar *>(data2.data()), out.get(), static_cast<size_t>(len), &AesKey, iv, AES_DECRYPT);

    else
        AES_cbc_encrypt(reinterpret_cast<const uchar *>(data2.data()), out.get(), static_cast<size_t>(len), &AesKey, iv, AES_ENCRYPT);

    out.get()[len] = '\0';


    return QByteArray(reinterpret_cast<char *>(out.get()), len);
}
QByteArray core::Crypto::cryptMtkNv(const QByteArray data, bool xflash)
{
    QByteArray result;
    const uint8_t *p = reinterpret_cast<const uint8_t*>(data.data());
    int len = sizeof(uint64_t);

    if (xflash)
    {
        while(len--)
        {
            result.push_back(((*p & 0xf0) >> 4) | ((*p & 0x0f) << 4));
            p++;
        }

        result = result.toHex().remove(15, 1);
    }
    return result;
}
