
#ifndef _filelib_H_
#define _filelib_H_

#include <string>

void wfile(const char *f, const void *data, int datalen)
{
    auto f1 = fopen(f, "wb");
    fwrite(data, 1, datalen, f1);
    fclose(f1);
}

std::string rfile(const char *f)
{
    auto f1 = fopen(f, "rb");
    fseek(f1, 0, FILE_END);
    auto dwBlobLen = ftell(f1);

    std::string s;
    s.resize(dwBlobLen);

    rewind(f1);
    auto len = fread(&s.front(), 1, dwBlobLen, f1);
    fclose(f1);

    s.resize(len);
    return s;
}

#endif
