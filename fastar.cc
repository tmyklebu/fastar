/*
 * fastar version 0
 * Copyright (c) 2013, Tor Myklebust and Marc Burns.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * The names of the authors may not be used to endorse or promote
 *       products derived from this software without specific prior written
 *       permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <memory>
#include <set>
#include <algorithm>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <attr/xattr.h>
#include <stdexcept>
#include <vector>
#include <map>
#include <string>
#include <functional>
#include <unordered_map>
#include <dirent.h>
#include <errno.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <queue>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdint.h>
using namespace std;

// Machine-specific configuration

static int pagesize = 0;

// TODO:  If the fs supports it, use FIEMAP or FIBMAP to figure out the extents
// of a directory.  Use the first extent instead of the inode number.

static int dirextents = 0;

#define FOR(i,n) for (int i=0;i<n;i++)

string strprintf(const char *fmt, ...) {
  va_list vargs;
  va_start(vargs, fmt);
  char *buf = 0;
  vasprintf(&buf, fmt, vargs);
  va_end(vargs);
  string ans = buf;
  free(buf);
  return ans;
}

template<typename T>
string T2string(T x) {
  static const int size = sizeof(T);
  string p(size, 0);
  FOR(i, size) p[i] = (x >> 8*(size - i - 1)) & 0xFF;
  return p;
}
template<typename T>
T string2T(const string &s) {
  const unsigned char *p = (const unsigned char*)&s[0];
  static const int size = sizeof(T);
  T res = 0;
  FOR(i, size) res |= (unsigned long long)(p[i]) << 8*(size - i - 1);
  return res;
}
template<typename T>
T cstring2T(const unsigned char ** s) {
  static const int size = sizeof(T);
  T res = 0;
  FOR(i, size) res |= (unsigned long long)((*s)[i]) << 8*(size - i - 1);
  *s += size;
  return res;
}
string length_prefixed(const string &s) {
  return T2string<uint64_t>(s.size())+s;
}

struct ffextent {
  ffextent(bool a, bool l, uint64_t o, uint64_t b, uint64_t le)
    : aligned(a), last(l), blk(b), off(o), len(le) { };
  bool aligned, last;
  uint64_t blk, off, len;
};

string base_dir;

struct fd_raii {
  int fd;
  fd_raii(int fd) : fd(fd) {}
  ~fd_raii() { close(fd); }
};

struct dir_raii {
  DIR *d;
  dir_raii(DIR *d) : d(d) {}
  ~dir_raii() { closedir(d); }
};

struct file_extents {
  std::vector<ffextent> extents;

  file_extents(int fd) {
    grab_extents_fiemap(fd);
  }

  file_extents(int fd, size_t filesz, int dirextents) {
    if(dirextents == 2)
      grab_extents_fiemap(fd);
    else if(dirextents == 1)
      grab_extents_fibmap(fd, filesz);
    else
      throw runtime_error("file_extents: directory extents requested and operation not supported");
  }

  void grab_extents_fibmap(int fd, size_t filesz) {
    size_t block = 0, blocksz = 0, nblocks;
    int res;
    while((res = ioctl(fd, FIGETBSZ, &blocksz)) < 0) {
      if(errno != EINTR) {
        throw runtime_error(strprintf("ioctl FIGETBSZ failed: %s", strerror(errno)));
      }
    }
    nblocks = (filesz + blocksz - 1) / blocksz;
    extents.reserve(nblocks);
    for(size_t i=0; i < nblocks; i++) {
      block = i;
      while((res = ioctl(fd, FIBMAP, &block)) < 0) {
        if(errno != EINTR) {
          throw runtime_error(strprintf("ioctl FIBMAP failed: %s", strerror(errno)));
        }
      }
      extents.push_back(
          ffextent(true,
            (i+1) == blocksz,
            i * blocksz,
            block,
            (size_t)min(blocksz, filesz - i * blocksz)));
    }
  }

  void grab_extents_fiemap(int fd) {
    struct fiemap extinfo;
    memset(&extinfo, 0, sizeof(struct fiemap));

    extinfo.fm_start = 0;
    extinfo.fm_length = ~0;
    extinfo.fm_extent_count = 0;

    while(ioctl(fd, FS_IOC_FIEMAP, &extinfo) < 0) {
      if(errno != EINTR)
        throw runtime_error(strprintf("FS_IOC_FIEMAP failed: %s", strerror(errno)));
    }

    while(1) {
      size_t len = sizeof(struct fiemap)
                 + extinfo.fm_mapped_extents * sizeof(struct fiemap_extent);
      struct fiemap * exts = (struct fiemap *)alloca(len);
      memset(exts, 0, len);

      exts->fm_start = 0;
      exts->fm_length = ~0;
      exts->fm_extent_count = extinfo.fm_mapped_extents;

      while(ioctl(fd, FS_IOC_FIEMAP, exts) < 0) {
        if(errno != EINTR)
          throw runtime_error(strprintf("FS_IOC_FIEMAP failed: %s", strerror(errno)));
      }
      if (exts->fm_mapped_extents == 0) return;
      if(!(exts->fm_extents[exts->fm_mapped_extents-1].fe_flags
          & FIEMAP_EXTENT_LAST))
        continue;

      extents.reserve(exts->fm_mapped_extents);
      for(uint32_t i = 0; i < exts->fm_mapped_extents; i++) {
        struct fiemap_extent * e = exts->fm_extents + i;
        if(e->fe_flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC
            | FIEMAP_EXTENT_ENCODED | FIEMAP_EXTENT_DATA_ENCRYPTED))
        {
          throw runtime_error(strprintf("bogus extent: %u", e->fe_flags));
        }
        if (!(e->fe_flags & FIEMAP_EXTENT_UNWRITTEN))
          extents.push_back(
              ffextent(!(e->fe_flags & FIEMAP_EXTENT_NOT_ALIGNED),
                e->fe_flags & FIEMAP_EXTENT_LAST,
                e->fe_logical,
                e->fe_physical,
                e->fe_length));
      }
      break;
    }
  }

  static int dir_extents_test(const char * d) {
    int fd = open(d, O_RDONLY), res;
    if(fd < 0) {
      throw runtime_error(strprintf("open(%s) failed: %s", d, strerror(errno)));
    }

    fd_raii r(fd);

    struct fiemap foo;
    memset(&foo, 0, sizeof(struct fiemap));
    while((res = ioctl(fd, FS_IOC_FIEMAP, &foo)) < 0) {
      if(errno != EINTR)
        break;
    }

    if(res == 0)
      return 2;

    int block = 0;
    while((res = ioctl(fd, FIBMAP, &block)) < 0) {
      if(errno != EINTR)
        break;
    }

    if(res == 0)
      return 1;

    return 0;
  }
};

struct inode_metadata {
  uint8_t kind; // regular, device, etc.
  uint64_t ino;
  uint16_t uid, gid;
  uint16_t perms;
  uint64_t size;
  uint32_t devno;
  uint64_t atime_sec, atime_nsec, mtime_sec, mtime_nsec;

  vector<char> _xattr_data;
  vector<int> xattr_name_idx;
  vector<int> xattr_val_idx;
  vector<pair<int, int> > extents;

  inode_metadata(const string & body, const string & xattrs) {
    const unsigned char * s = (const unsigned char *)&body[0];
    assert(body.size() == bodysize());

    kind = cstring2T<int8_t>(&s);
    ino = cstring2T<uint64_t>(&s);
    uid = cstring2T<uint16_t>(&s);
    gid = cstring2T<uint16_t>(&s);
    perms = cstring2T<uint16_t>(&s);
    size = cstring2T<uint64_t>(&s);
    atime_sec = cstring2T<uint64_t>(&s);
    atime_nsec = cstring2T<uint64_t>(&s);
    mtime_sec = cstring2T<uint64_t>(&s);
    mtime_nsec = cstring2T<uint64_t>(&s);

    _xattr_data.resize(xattrs.size());
    memcpy(&_xattr_data[0], &xattrs[0], xattrs.size());

    int start = 0;
    bool iskey = true;
    FOR(i, _xattr_data.size()) {
      if(_xattr_data[i] == '\0') {
        if(iskey) {
          xattr_name_idx.push_back(start);
        } else {
          xattr_val_idx.push_back(start);
        }
        start = i+1;
        iskey = ~iskey;
      }
    }
  }

  inode_metadata() {}

  string serialise() const {
    string xattrs;
    FOR(i, xattr_name_idx.size()) {
      xattrs += &_xattr_data[xattr_name_idx[i]];
      xattrs += '\0';
      xattrs += &_xattr_data[xattr_val_idx[i]];
      xattrs += '\0';
    }

    return
        T2string<int8_t>(kind)
      + T2string<uint64_t>(ino)
      + T2string<uint16_t>(uid)
      + T2string<uint16_t>(gid)
      + T2string<uint16_t>(perms)
      + T2string<uint64_t>(size)
      + T2string<uint64_t>(atime_sec)
      + T2string<uint64_t>(atime_nsec)
      + T2string<uint64_t>(mtime_sec)
      + T2string<uint64_t>(mtime_nsec)
      + length_prefixed(xattrs);
  }

  static size_t bodysize() {
    return
        sizeof(kind)
      + sizeof(ino)
      + sizeof(uid)
      + sizeof(gid)
      + sizeof(perms)
      + sizeof(size)
      + sizeof(atime_sec)
      + sizeof(atime_nsec)
      + sizeof(mtime_sec)
      + sizeof(mtime_nsec);
  }

  void fill_stat_md(const struct stat &st) {
    if (S_ISREG(st.st_mode)) kind = 0;
    else if (S_ISDIR(st.st_mode)) kind = 1;
    else if (S_ISCHR(st.st_mode)) kind = 2;
    else if (S_ISBLK(st.st_mode)) kind = 3;
    else if (S_ISFIFO(st.st_mode)) kind = 4;
    else if (S_ISLNK(st.st_mode)) kind = 5;
    else if (S_ISSOCK(st.st_mode)) kind = 6;
    else throw runtime_error("unknown file kind");
    uid = st.st_uid;
    gid = st.st_gid;
    ino = st.st_ino;
    perms = st.st_mode & 0xffff;
    size = st.st_size;
    devno = st.st_rdev;
    atime_sec = st.st_atim.tv_sec;
    atime_nsec = st.st_atim.tv_nsec;
    mtime_sec = st.st_mtim.tv_sec;
    mtime_nsec = st.st_mtim.tv_nsec;
  }

  void fill_xattr_md(function<ssize_t(char *, size_t)> listxa,
                     function<ssize_t(const char*, void*, size_t)> getxa) {
    ssize_t siz = listxa(0, 0);
    if (siz < 0) throw runtime_error(strprintf("listxa(0,0): %s", strerror(errno)));
    _xattr_data.resize(siz);
    siz = listxa(&_xattr_data[0], siz);
    if (siz < 0) throw runtime_error(strprintf("listxa: %s", strerror(errno)));
    int last = 0;
    FOR(i, _xattr_data.size()) if (_xattr_data[i] == 0)
      xattr_name_idx.push_back(last), last = i+1;
    if (last != _xattr_data.size())
      throw runtime_error("listxa didn't 0-terminate");

    FOR(i, xattr_name_idx.size()) {
      siz = getxa(xattr_name(i), 0, 0);
      if (siz < 0) throw runtime_error(strprintf("getxa(%s,0,0): %s",
          xattr_name(i), strerror(errno)));
      size_t back = _xattr_data.size();
      _xattr_data.resize(back + siz);
      siz = getxa(xattr_name(i), &_xattr_data[back], siz);
      if (siz < 0) throw runtime_error(strprintf("getxa(%s): %s",
          xattr_name(i), strerror(errno)));
      if (_xattr_data[siz + back - 1] != 0)
        throw runtime_error("getxa didn't 0-terminate");
    }
  }

  inode_metadata(const char *path) {
    struct stat st;
    if (lstat(path, &st))
      throw runtime_error(strprintf("lstat(%s): %s", path, strerror(errno)));
    fill_stat_md(st);
    fill_xattr_md([path](char *l, size_t s){return llistxattr(path,l,s);},
                  [path](const char *n, void *v, size_t s){
                      return lgetxattr(path,n,v,s); });
  }

  inode_metadata(int fd) {
    struct stat st;
    if (fstat(fd, &st))
      throw runtime_error(strprintf("fstat(%i): %s", fd, strerror(errno)));
    fill_stat_md(st);
    fill_xattr_md([fd](char *l, size_t s){return flistxattr(fd,l,s);},
                  [fd](const char *n, void *v, size_t s){
                      return fgetxattr(fd,n,v,s); });
  }

#define SAFE_SYSCALL(f, p, ...) do {\
  while(f(p, ##__VA_ARGS__) < 0) {\
    if(errno != EINTR) {\
      throw runtime_error(strprintf("%s(%s): %s", #f, p, strerror(errno)));\
    }\
  }\
} while(0)
#define SAFE_SYSCALL0(f, p, ...) do {\
  while(f(p, ##__VA_ARGS__) < 0) {\
    if(errno != EINTR) {\
      throw runtime_error(strprintf("%s: %s", #f, strerror(errno)));\
    }\
  }\
} while(0)

  void restore(const char *path, const char *maybe_linktarget) {
    mode_t kind2S_[] = { S_IFREG, 0, S_IFCHR, S_IFBLK, S_IFIFO, 0, S_IFSOCK };
    switch(kind) {
      case 0: case 2: case 3: case 4: case 6:
        if (kind != 2 && kind != 3) devno = 0;
        SAFE_SYSCALL(mknod, path, kind2S_[kind] | 0640, devno);
        break;
      case 1:
        SAFE_SYSCALL(mkdir, path, 0750);
        break;
      case 5:
        SAFE_SYSCALL(symlink, maybe_linktarget, path);
        break;
      default:
        throw runtime_error("weird kind");
    }
    if(kind == 0) {
      SAFE_SYSCALL(truncate, path, (off_t)size);
    }
  }

  void fixup(const char *path) {
    if(kind != 5)
      SAFE_SYSCALL(chmod, path, (mode_t)perms);
    SAFE_SYSCALL(lchown, path, (uid_t)uid, (gid_t)gid);
    if(xattr_val_idx.size() != xattr_name_idx.size()) {
      throw runtime_error("restore: xattr_name_idx and xattr_val_idx have differing sizes");
    }
    FOR(i, xattr_name_idx.size())
      SAFE_SYSCALL(lsetxattr, path,
          &_xattr_data[xattr_name_idx.size()],
          &_xattr_data[xattr_val_idx.size()],
          strlen(&_xattr_data[xattr_val_idx.size()]), 0);
    struct timespec ts[2];
    memset(&ts, 0, sizeof(struct timespec[2]));
    ts[0].tv_sec = atime_sec;
    ts[0].tv_nsec = atime_nsec;
    ts[1].tv_sec = mtime_sec;
    ts[1].tv_nsec = mtime_nsec;
    SAFE_SYSCALL0(utimensat, AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
  }

  /* XXX
  string tostring() {
    const char * kinds[] = {"fil", "dir", "chr", "blk", "fifo", "lnk", "sock"};
    return strprintf("%s %u:%u %o %lu %u %lu %lu %lu",
        kinds[kind], uid, gid, perms, size, devno, atime, ctime, mtime);
  }
  */

  char *xattr_name(int i) {
    return &_xattr_data[xattr_name_idx[i]];
  }
  const char *xattr_name(int i) const {
    return &_xattr_data[xattr_name_idx[i]];
  }
  char *xattr_val(int i) {
    return &_xattr_data[xattr_val_idx[i]];
  }
  const char *xattr_val(int i) const {
    return &_xattr_data[xattr_val_idx[i]];
  }
  char *xattr(const char *p) {
    FOR(i, xattr_name_idx.size()) if (!strcmp(xattr_name(i), p))
      return xattr_val(i);
    return 0;
  }
  const char *xattr(const char *p) const {
    FOR(i, xattr_name_idx.size()) if (!strcmp(xattr_name(i), p))
      return xattr_val(i);
    return 0;
  }
  char *xattr(const string &s) { return xattr(s.c_str()); }
  const char *xattr(const string &s) const { return xattr(s.c_str()); }
  int nxattrs() const { return xattr_name_idx.size(); }
};

struct workqueue_base {
  mutex mu;
  condition_variable cv;
  bool done;

  vector<thread> vt;
  bool joined;

  virtual void worker() = 0;

  workqueue_base() {
    done = false;
    joined = false;
  }

  void start(int threads) {
    for (int i = 0; i < threads; i++)
      vt.push_back(thread([this](){worker();}));
  }

  virtual ~workqueue_base() {
    if (!joined) join();
  }

  void join() {
    {
      lock_guard<mutex> lg(mu);
      done = true;
      cv.notify_all();
    }
    for (int i = 0; i < vt.size(); i++)
      vt[i].join();
    joined = true;
  }
};

struct disk_workqueue : workqueue_base {
  multimap<int, function<void()> > q;

  void push(key_t key, function<void()> f) {
    lock_guard<mutex> g(mu);
    q.insert(make_pair(key, f));
    cv.notify_one();
  }

  void worker() {
    key_t lastkey = 0;
    while (1) {
      function<void()> f;
      {
        unique_lock<mutex> lg(mu);
        while (!q.size()) {
          if (done) return;
          cv.wait(lg);
        }
        auto it = q.lower_bound(lastkey);
        if (it == q.end()) it = q.begin();
        f = it->second;
        q.erase(it);
      }
      f();
    }
  }

  disk_workqueue(int threads = 64) : workqueue_base() { start(threads); }
};

struct dirtree_walker : disk_workqueue {
  typedef function<void(const string &, const inode_metadata &)> handler_t;

  handler_t handler;

  int scan_directory(string dir) {
    DIR *d = opendir(dir.c_str());
    if (!d) {
      fprintf(stderr, "opendir(%s): %s\n", dir.c_str(), strerror(errno));
      return -1;
    }

    dir_raii raii(d);

    dirent de;
    dirent *res;

    while (1) {
      int st = readdir_r(d, &de, &res);
      if (st)
        throw runtime_error(strprintf("readdir(%s): %s",
            dir.c_str(), strerror(errno)));
      if (!res) break;
      if (!strcmp(de.d_name, ".")) continue;
      if (!strcmp(de.d_name, "..")) continue;

      string name = dir + "/" + de.d_name;
      ino_t ino = de.d_ino;
      try {
        inode_metadata md(name.c_str());
        handler(name, md);
        if (md.kind == 1)
          push(ino, [name,this]{scan_directory(name);});
      } catch (exception &e) {
        fprintf(stderr, "while processing %s: %s\n", name.c_str(), e.what());
        throw e;
      }
    }

    return 0;
  }

  dirtree_walker(const char *dt, handler_t handler, int threads = 64)
      : disk_workqueue(threads), handler(handler) {
    push(0, [dt,this]{scan_directory(dt); return 0;});
  }
};

struct pending_output {
  virtual vector<iovec> get_iovec() = 0;
  virtual ~pending_output() {}
};

struct pending_string_output : pending_output {
  string s;
  pending_string_output(const string &s) : s(s) {}

  vector<iovec> get_iovec() {
    vector<iovec> iov(1);
    iov[0].iov_base = &s[0];
    iov[0].iov_len = s.size();
    return iov;
  }
};

struct pending_iovec_output : pending_output {
  vector<iovec> v;
  pending_iovec_output(const vector<iovec> &v) : v(v) {}

  vector<iovec> get_iovec() { return v; }
};

struct pending_datapkt_output : pending_output {
  string hdr;
  char *data;
  int off;
  size_t datalen;

  pending_datapkt_output(const string &hdr, char *payload, int off, size_t len)
    : hdr(hdr), data(payload), off(off), datalen(len) {}

  ~pending_datapkt_output() {
    delete[] data;
  }

  vector<iovec> get_iovec() {
    vector<iovec> iov(2);
    iov[0].iov_base = &hdr[0];
    iov[0].iov_len = hdr.size();
    iov[1].iov_base = data + off;
    iov[1].iov_len = datalen;
    return iov;
  }
};

struct outputter : workqueue_base {
  queue<unique_ptr<pending_output> > q;
  int totsiz;
  condition_variable qfull;

  void push(unique_ptr<pending_output> po, size_t siz) {
    unique_lock<mutex> lg(mu);
    while (totsiz > (64<<20)) qfull.wait(lg);
    q.push(move(po));
    totsiz += siz;
    cv.notify_all();
  }

  outputter() : workqueue_base() {
    totsiz = 0;
    start(1);
  }

  void worker() {
    while (1) {
      unique_ptr<pending_output> po;
      vector<iovec> iov;
      { unique_lock<mutex> lg(mu);
        while (!q.size()) {
          if (done) return;
          cv.wait(lg);
        }
        po = move(q.front());
        q.pop();
        iov = po->get_iovec();
        FOR(i, iov.size()) totsiz -= iov[i].iov_len;
      }
      dowritev(iov);
      qfull.notify_all();
    }
  }

  static void dowritev(vector<iovec> v) {
    iovec *vec = &v[0];
    int vecs = v.size();
    while (vecs) {
      ssize_t len = writev(1, vec, vecs);
      if (len < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "writev failed.  iovec was %i long:\n", vecs);
        FOR(i, vecs)
          fprintf(stderr, "%p %zu\n", vec[i].iov_base, vec[i].iov_len);
        throw runtime_error(strprintf("outputter couldn't output: %s",
            strerror(errno)));
      }
      while (vecs && len >= vec[0].iov_len) {
        len -= vec[0].iov_len;
        vecs--;
        vec++;
      }
      if (len) {
        vec[0].iov_len -= len;
        vec[0].iov_base = (char *)vec[0].iov_base + len;
      }
    }
  }
} output;

void enqueue_block(const string &s) {
  output.push(unique_ptr<pending_output>(
      new pending_string_output(s)), s.size());
}

void enqueue_iovec(const vector<iovec> &v) {
  size_t sz = 0;
  FOR(i, v.size()) sz += v[i].iov_len;
  output.push(unique_ptr<pending_output>(
      new pending_iovec_output(v)), sz);
}

void enqueue_datapkt(const string &h, char *p, int off, size_t len) {
  output.push(unique_ptr<pending_output>(
      new pending_datapkt_output(h, p, off, len)), h.size() + len);
}

namespace std {
  template <typename T>
  bool operator<(const vector<T> &, const vector<T> &) { return false; }
}

struct inode_canon {
  mutex mu;
  unordered_map<ino_t, string> m;

  bool canon(ino_t inode, string &s) {
    lock_guard<mutex> lg(mu);
    if (m.count(inode)) {
      s = m[inode];
      return true;
    }
    else {
      m[inode] = s;
      return false;
    }
  }
} ino_can;

struct pending_io {
  string file;
  uint64_t blk;
  uint64_t off, len;
  int last;
  bool operator<(const pending_io &p) const { return blk < p.blk; }
  pending_io(){}
  pending_io(string s, ffextent e)
    : file(s), blk(e.blk), off(e.off), len(e.len), last(e.last) {}
};

struct data_workqueue : workqueue_base {
  multiset<pending_io> pend;

  static void doio(const pending_io &p) {
    char *_buf = new char[p.len + pagesize];
    unique_ptr<char[]> argh(_buf);
    char *buf = _buf;
    buf += pagesize - ((intptr_t)buf & (pagesize - 1));
    sadface:
    int fd = open(p.file.c_str(), O_RDONLY | O_DIRECT);
    while (fd < 0) {
      if (errno == EINTR) goto sadface;
      throw runtime_error(strprintf("open(%s): %s",
          p.file.c_str(), strerror(errno)));
    }
    fd_raii raii(fd);
    while (lseek(fd, p.off, SEEK_SET) < 0) {
      if (errno != EINTR)
        throw runtime_error(strprintf("lseek: %s", strerror(errno)));
    }
    int left = p.len;
    char *fub = buf;
    while (left) {
      int red = read(fd, fub, left);
      if (red < 0) {
        if (errno == EINTR) continue;
        throw runtime_error(strprintf("read(%s): %s",
            p.file.c_str(), strerror(errno)));
      }
      if (red == 0) {
        if (!p.last)
          fprintf(stderr, "unexpected eof reading %s", p.file.c_str());
        break;
      }
      fub += red;
      left -= red;
    }

    argh.release();
    string hdr;
    hdr += length_prefixed(p.file);
    hdr += "d";
    hdr += T2string<uint64_t>(p.off);
    hdr += T2string<uint64_t>(fub-buf);
    enqueue_datapkt(hdr, _buf, buf-_buf, fub-buf);
  }

  void worker() {
    uint64_t last_blk = rand();
    while (1) {
      pending_io p;
      p.blk = last_blk;
      { unique_lock<mutex> lg(mu);
        while (!pend.size()) {
          if (done) return;
          cv.wait(lg);
        }
        auto it = pend.lower_bound(p);
        if (it == pend.end()) it = pend.begin();
        p = *it;
        last_blk = p.blk;
        pend.erase(it);
      }
      doio(p);
    }
  }

  void push(pending_io &&pe) {
    unique_lock<mutex> lk(mu);
    pend.insert(move(pe));
    cv.notify_one();
  }
};

struct data_grabber {
  mutex mu;
  vector<pair<uint64_t, pair<string, vector<ffextent> > > > bigwork, smallwork;
  data_workqueue big, small;

  void doit() {
    static const int grab_nthread = 16;
    static const int small_grab_nthread = 64;
    static const int bigness_threshold = 65536; // bytes
    big.start(grab_nthread); small.start(small_grab_nthread);
    FOR(i, bigwork.size())
      FOR(j, bigwork[i].second.second.size())
        big.push(pending_io(bigwork[i].second.first,
                            bigwork[i].second.second[j]));

    sort(smallwork.begin(), smallwork.end());
    FOR(i, smallwork.size())
      FOR(j, smallwork[i].second.second.size()) {
        const string &foo = smallwork[i].second.first;
        ffextent &e = smallwork[i].second.second[j];
        if (e.len > bigness_threshold) big.push(pending_io(foo, e));
        else small.push(pending_io(foo, e));
      }
    big.join(); small.join();
  }

  void coalesce() {
    static const uint64_t max_read_chunk_size = 32<<20;
    // break up the big reads.
    vector<pair<uint64_t, pair<string, vector<ffextent> > > > newwork;
    FOR(i, bigwork.size()) {
      string &filename = bigwork[i].second.first;
      vector<ffextent> &exts = bigwork[i].second.second;
      vector<ffextent> eout;
      int cursz = 0;
      FOR(j, exts.size()) {
        again:
        if (cursz + exts[j].len <= max_read_chunk_size)
          eout.push_back(exts[j]);
        else if (eout.size()) {
          newwork.push_back(make_pair(bigwork[i].first,
              make_pair(bigwork[i].second.first, eout)));
          eout.clear();
          goto again;
        } else {
          ffextent e = exts[j];
          while (e.len > 0) {
            ffextent f = e;
            f.len = min(e.len, max_read_chunk_size);
            newwork.push_back(make_pair(f.blk,
                make_pair(filename, vector<ffextent>(1, f))));
            e.off += f.len;
            e.len -= f.len;
            e.blk += f.len;
          }
        }
      }
      if (eout.size())
        newwork.push_back(make_pair(bigwork[i].first,
            make_pair(bigwork[i].second.first, eout)));
    }

    // TODO: deal with small chunks belonging to the same file...somehow.
    FOR(i, smallwork.size()) newwork.push_back(smallwork[i]);

    smallwork.swap(newwork);
    bigwork.clear();
  }

  int add(const string &name, const inode_metadata &md) {
    string newname = name;
    if (ino_can.canon(md.ino, newname)) {
      string block = length_prefixed(name) + "\007"
          + length_prefixed(newname);
      enqueue_block(block);
      return 1;
    }

    sadface:
    int fd = open(name.c_str(), O_RDONLY | O_DIRECT);
    if (fd < 0) {
      if (errno == EINTR) goto sadface;
      if (errno == EACCES) {
        fprintf(stderr, "warning: open(%s): %s\n", name.c_str(),
            strerror(errno));
        return 0;
      }
      throw runtime_error(strprintf("open(%s): %s", name.c_str(),
          strerror(errno)));
    }
    fd_raii raii(fd);
    try {
      file_extents ext(fd);
      size_t totlen = 0;
      FOR(i, ext.extents.size()) totlen += ext.extents[i].len;
      if (totlen == 0) return 0;
      lock_guard<mutex> lg(mu);
      (totlen > 32<<20 ? bigwork : smallwork).push_back(make_pair(
          ext.extents[0].blk, make_pair(name, ext.extents)));
    } catch (exception &e) {
      fprintf(stderr, "warning: failed to fetch extents for %s: %s\n",
           name.c_str(), e.what());
    }
    return 0;
  }
} grab;

void handle_dent(const string &name, const inode_metadata &md) {
  string prefix = length_prefixed(name);
  switch (md.kind) {
    case 1: case 2: case 3: case 4: case 6: {
      enqueue_block(prefix + md.serialise());
    } break;
    case 5: {
      string foo = prefix + md.serialise();
      char buf[8192];
      while (1) {
        int len = readlink(name.c_str(), buf, 8192);
        if (len < 0) {
          if (errno == EINTR) continue;
          throw runtime_error(strprintf("readlink(%s): %s", name.c_str(),
              strerror(errno)));
        }
        foo += length_prefixed(string(buf, buf+len));
        break;
      }
      enqueue_block(foo);
    } break;
    case 0: {
      if (!grab.add(name, md))
        enqueue_block(prefix + md.serialise());
    } break;
    default: throw runtime_error(strprintf("weird kind %i", md.kind));
  }
}

struct eof_exception : exception {};

int bytes_read = 0;
#define FREAD(targ,len,nmemb) do { \
        int rv = fread(targ, len, nmemb, f); \
        if (rv != nmemb) { \
          if (feof(f)) abort(); throw runtime_error("unexpected eof"); \
          throw runtime_error(strprintf("fread: %s", strerror(errno))); \
        } \
        bytes_read += rv * nmemb; \
      } while (0)
#define FREAD_EOF(targ,len,nmemb) do { \
        int rv = fread(targ, len, nmemb, f); \
        if (rv != nmemb) { \
          if (feof(f)) throw eof_exception(); \
          throw runtime_error(strprintf("fread: %s", strerror(errno))); \
        } \
        bytes_read += rv * nmemb; \
      } while (0)

string read_lenprestring(FILE *f) {
  string bfr(8,'\0');
  FREAD_EOF(&bfr[0], 1, 8);
  uint64_t len = string2T<uint64_t>(bfr);
  string s(len, '\0');
  FREAD(&s[0], 1, len);
  return s;
}

inode_metadata get_inode_md(char kind, FILE * f) {
  ungetc(kind, f);
  char bfr1[inode_metadata::bodysize() + 6];
  char * p = bfr1;
  FREAD(p, inode_metadata::bodysize(), 1);
  p += inode_metadata::bodysize();
  if(kind == 2 || kind == 3) {
    FREAD(p, 1, 2);
    p += 2;
  }

  string xattrs = read_lenprestring(f);
  string allbfr = string(bfr1, p);

  return inode_metadata(allbfr, xattrs);
}

bool dry_run = false;

void restore_data(string filename, FILE *f) {
  static const uint64_t block_size = 65536;
  string lbfr(8, '\0');
  FREAD(&lbfr[0], 1, 8);
  uint64_t offset = string2T<uint64_t>(lbfr);
  FREAD(&lbfr[0], 1, 8);
  uint64_t datalen = string2T<uint64_t>(lbfr);

  if (!dry_run) {
    sadface:
    int fd = open(filename.c_str(), O_WRONLY);
    if (fd < 0) {
      if (errno == EINTR) goto sadface;
      throw runtime_error(strprintf("open(%s): %s", filename.c_str(),
          strerror(errno)));
    }
    fd_raii raii(fd);
    SAFE_SYSCALL0(lseek, fd, offset, SEEK_SET);

    while (datalen) {
      char buf[block_size];
      int to_read = min(block_size, datalen);
      int len = fread(buf, 1, to_read, f);
      if (len != to_read) {
        if (feof(f))
          throw runtime_error("fread came up short during data block "
              "read: unexpected eof");
        throw runtime_error(strprintf("fread came up short during data block "
            "read: %s", strerror(errno)));
      }
      datalen -= len;
      char *p = buf;
      while (len) {
        int rit = write(fd, p, len);
        if (rit < 0) {
          if (errno == EINTR) continue;
          throw runtime_error(strprintf("write: %s", strerror(errno)));
        }
        if (!rit) {
          fprintf(stderr, "write() unexpectedly returned 0\n");
          return;
        }
        p += rit;
        len -= rit;
      }
    }
  } else {
    while (datalen) {
      char buf[block_size];
      int to_read = min(block_size, datalen);
      int len = fread(buf, 1, to_read, f);
      fprintf(stderr, "I want to write %i bytes; %i remain.\n", len, datalen);
      datalen -= len;
    }
  }
}

vector<pair<string, inode_metadata> > node_fixup_list;

void fixup_nodes() {
  FOR(i, node_fixup_list.size())
    node_fixup_list[i].second.fixup(node_fixup_list[i].first.c_str());
}

void restore(FILE *f) {
  while (1) {
    int c;
    string from = read_lenprestring(f);
    switch ((c = getc(f))) {
      case 0: case 1: {
        inode_metadata md = get_inode_md(c, f);
        md.restore(from.c_str(), 0);
        node_fixup_list.push_back(make_pair(from, md));
      } break;
      case 2: case 3: case 4: case 6: {
        inode_metadata md = get_inode_md(c, f);
        md.restore(from.c_str(), 0);
        md.fixup(from.c_str());
      } break;
      case 5: {
        inode_metadata md = get_inode_md(c, f);
        string to = read_lenprestring(f);
        md.restore(from.c_str(), to.c_str());
        md.fixup(from.c_str());
      } break;
      case 7: { // hardlink
        string to = read_lenprestring(f);
        SAFE_SYSCALL0(link, to.c_str(), from.c_str());
      } break;
      case 'd': { // data block
        restore_data(from, f);
      } break;
      default:
        throw runtime_error(strprintf("bogus type 0x%x", c));
    }
  }
}

int main(int argc, char **argv) {
  int argno = 1;
  int unpack = 0;
  while (argno < argc && argv[argno][0] == '-') {
    if (!strcmp(argv[argno], "-d")) unpack = 1;
    else {
      fprintf(stderr, "unknown flag %s\n", argv[argno]);
      exit(-1);
    }
    argno++;
  }
  pagesize = sysconf(_SC_PAGESIZE);
  if(pagesize < 1) {
    fprintf(stderr, "bad: sysconf(_SC_PAGESIZE) = %d\n", pagesize);
    exit(-1);
  }
  if (!unpack) {
    dirextents = file_extents::dir_extents_test(".");
    dirtree_walker w(".", handle_dent);
    w.join();
    grab.coalesce();
    grab.doit();
    output.join();
  } else {
    try {
      restore(stdin);
    } catch (eof_exception &e) {}
    fixup_nodes();
  }
}
