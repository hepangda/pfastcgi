/**
 * MIT License
 *
 * Copyright (c) 2018 hepangda
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 **/

#ifndef PFASTCGI_PFASTCGI_H
#define PFASTCGI_PFASTCGI_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>

namespace pfcgi {

using Byte = unsigned char;

const int kFcgiVersion = 1;
const int kFcgiKeepAlive = 1;

enum FcgiType {
  kTypeBegin = 1,
  kTypeAbort = 2,
  kTypeEnd = 3,
  kTypeParams = 4,
  kTypeStdin = 5,
  kTypeStdout = 6,
  kTypeStderr = 7,
  kTypeData = 8,
  kTypeGetValues = 9,
  kTypeValueResult = 10,
  kTypeUnknown = 11
};

enum FcgiRole { kRoleResponder = 1, kRoleAuthorizer = 2, kRoleFilter = 3 };

struct FcgiHeader {
  Byte version;
  Byte type;
  Byte request_id1;
  Byte request_id0;
  Byte content_length1;
  Byte content_length0;
  Byte padding_length;
  Byte reserved;

  FcgiHeader() {}

  FcgiHeader(FcgiType type, int content_length, int request_id = 1,
             int padding_length = 0)
      : version(kFcgiVersion),
        type(type),
        request_id1((request_id >> 8) & 0xff),
        request_id0(request_id & 0xff),
        content_length1((content_length >> 8) & 0xff),
        content_length0(content_length & 0xff),
        padding_length(padding_length),
        reserved(0) {}

  int request_id() const { return (request_id1 << 8) + request_id0; }

  int content_length() const {
    return (content_length1 << 8) + content_length0;
  }

  void set_request_id(int request_id) {
    request_id1 = (request_id >> 8) & 0xff;
    request_id0 = request_id & 0xff;
  }

  void set_content_length(int content_length) {
    content_length1 = (content_length >> 8) & 0xff;
    content_length0 = content_length & 0xff;
  }
};

struct FcgiRequestBeginBody {
  Byte role1;
  Byte role0;
  Byte flags;
  Byte reserved[5];

  FcgiRequestBeginBody() {}

  FcgiRequestBeginBody(int role, bool keep_alive)
      : role1((role >> 8) & 0xff), role0(role & 0xff), flags(keep_alive) {}

  int role() const { return (role1 << 8) + role0; }

  bool keep_alive() const { return flags & kFcgiKeepAlive; }

  void set_keep_alive(bool keep_alive) {
    flags = keep_alive ? kFcgiKeepAlive : 0;
  }

  void set_role(FcgiRole role) {
    role1 = (role >> 8) & 0xff;
    role0 = role & 0xff;
  }
};

struct FcgiRequestBegin {
  FcgiHeader header;
  FcgiRequestBeginBody body;
};

// struct FcgiRequestEndBody {
//   unsigned char appStatusB3;
//   unsigned char appStatusB2;
//   unsigned char appStatusB1;
//   unsigned char appStatusB0;
//   unsigned char protocolStatus;
//   unsigned char reserved[3];
// };

struct FcgiParams {
  Byte name_length3;
  Byte name_length2;
  Byte name_length1;
  Byte name_length0;
  Byte value_length3;
  Byte value_length2;
  Byte value_length1;
  Byte value_length0;

  FcgiParams() {}

  FcgiParams(int name_length, int value_length)
      : name_length3((name_length >> 24) | 0x80),
        name_length2(name_length >> 16),
        name_length1(name_length >> 8),
        name_length0(name_length),
        value_length3((value_length >> 24) | 0x80),
        value_length2(value_length >> 16),
        value_length1(value_length >> 8),
        value_length0(value_length) {}

  // TODO: finish name_length()
  // int name_length() const { return (name_length3 << 24) & 0x0F; }

  void set_name_length(int name_length) {
    name_length3 = (name_length >> 24) | 0x80;
    name_length2 = name_length >> 16;
    name_length1 = name_length >> 8;
    name_length0 = name_length;
  }
};

class FcgiManager {
 public:
  virtual ~FcgiManager() { closeSocket(); }

  virtual int start(const char *addr, int port) = 0;

  inline int doRead(void *buf, size_t length, int flags = 0) const {
    return ::recv(fcgifd_, buf, length, flags);
  }

  inline int doWrite(void *buf, size_t length, int flags = 0) const {
    return ::send(fcgifd_, buf, length, flags);
  }

  FcgiHeader readHeader() const {
    FcgiHeader header;
    doRead(&header, sizeof(header));
    return header;
  }

  int startParams(FcgiRole role, bool keep_alive, int request_id) const {
    FcgiRequestBegin msg{{kTypeBegin, sizeof(FcgiRequestBeginBody), request_id},
                         {role, keep_alive}};

    return doWrite(&msg, sizeof(msg));
  }

  int sendParams(const char *key, const char *value, int request_id) const {
    static constexpr auto kHeaderLength =
        sizeof(FcgiParams) + sizeof(FcgiHeader);

    auto key_length = strlen(key), value_length = strlen(value),
         all_length = kHeaderLength + key_length + value_length;

    std::unique_ptr<Byte[]> buf(new Byte[all_length]);
    new (buf.get())
        FcgiHeader(kTypeParams, key_length + value_length, request_id);
    new (buf.get() + sizeof(FcgiHeader)) FcgiParams(key_length, value_length);

    memcpy(buf.get() + kHeaderLength, key, key_length);
    memcpy(buf.get() + kHeaderLength + key_length, value, value_length);

    return doWrite(buf.get(), all_length);
  }

  int endParams(int requestID) const {
    FcgiHeader header(kTypeParams, 0, requestID);
    return doWrite(&header, sizeof(header));
  }

 protected:
  inline int fcgifd() const { return fcgifd_; }
  inline void set_fcgifd(const int fcgifd) { fcgifd_ = fcgifd; }
  inline void closeSocket() {
    if (fcgifd_ != -1) close(fcgifd_);
  }

 private:
  int fcgifd_ = -1;

  // -1 represents END OF REQUEST
  // 0  represents NO
  // 1  represents YES
  // int pkgType(FcgiPreread fp) {
  //   if (fp.type == FcgiType::END) return -1;
  //   if (fp.type != FcgiType::STDOUT && fp.type != FcgiType::STDERR) return 0;
  //   return (fp.contentLength > 0) ? 1 : 0;
  // }

  // inline int readContent(FcgiPreread pre, void *buffer) {
  //   std::shared_ptr<char> padding(new char[pre.paddingLength],
  //                                 std::default_delete<char[]>());
  //   return readContent(pre, buffer, padding.get());
  // }

  // int readContent(FcgiPreread pre, void *buffer, void *paddingBuffer) {
  //   int res = doRead(buffer, pre.contentLength);
  //   doRead(paddingBuffer, pre.paddingLength);
  //   return res;
  // }
};

class FcgiManagerINET : public FcgiManager {
 public:
  FcgiManagerINET(const char *addr, const int port) { start(addr, port); }
  int start(const char *addr, const int port) override {
    assert(port >= 0);
    closeSocket();

    sockaddr_in sktaddr;
    memset(&sktaddr, 0, sizeof(sockaddr_in));
    sktaddr.sin_family = AF_INET;
    sktaddr.sin_port = htons(port);

    if (inet_pton(AF_INET, addr, &sktaddr.sin_addr) <= 0) {
      return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    set_fcgifd(fd);
    return connect(fd, (sockaddr *)&sktaddr, sizeof(sockaddr_in));
  }
};

class FcgiManagerUnix : public FcgiManager {
 public:
  FcgiManagerUnix(const char *path) { start(path); }

  int start(const char *path, const int padding = 0) override {
    closeSocket();

    sockaddr_un sktaddr;
    memset(&sktaddr, 0, sizeof(sockaddr_un));
    sktaddr.sun_family = AF_UNIX;
    strcpy(sktaddr.sun_path, path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0),
        size = offsetof(sockaddr_un, sun_path) + strlen(sktaddr.sun_path);
    set_fcgifd(fd);
    return connect(fd, (sockaddr *)&sktaddr, size);
  }
};

}  // namespace pfcgi

#endif // PFASTCGI_PFASTCGI_H 