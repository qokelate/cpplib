#ifndef _httplib_ext_H_
#define _httplib_ext_H_

#include <string>
#include "httplib.h"

inline std::string get_request_body(const httplib::ContentReader& content_reader)
{
    std::string body2;
    content_reader([&](const char* data, size_t data_length) {
        body2.append(data, data_length);
        return true;
    });
    return body2;
}

#endif

