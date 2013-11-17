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
#include <utime.h>
using namespace std;

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

string int2string(int sz) {
  string p((char *)&sz, (char *)(&sz+1));
  return p;
}
int string2int(const string &s) {
  return *(int *)&s[0];
}
string ll2string(long long sz) {
  string p((char *)&sz, (char *)(&sz+1));
  return p;
}
string length_prefixed(const string &s) {
  int sz = s.size();
  string p((char *)&sz, (char *)(&sz+1));
  return p+s;
}

struct ffextent {
  ffextent(bool a, bool l, uint64_t o, uint64_t b, uint64_t le)
    : aligned(a), last(l), blk(b), off(o), len(le) { };
  bool aligned, last;
  uint64_t blk, off, len;
};

string base_dir;

struct file_extents {
  std::vector<ffextent> extents;

  file_extents(int fd) {
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
      // XXX HACK:  Make valgrind shut up.
      //memset(exts, 0, sizeof(struct fiemap));
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
};

struct inode_metadata {
  int kind; // regular, device, etc.
  int ino;
  int uid, gid;
  int perms;
  size_t size;
  dev_t devno;
  time_t atime, ctime, mtime;

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
    atime = st.st_atime;
    mtime = st.st_mtime;
    ctime = st.st_ctime;
  }

  vector<char> _xattr_data;
  vector<int> xattr_name_idx;
  vector<int> xattr_val_idx;
  vector<pair<int, int> > extents;

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

  inode_metadata() {}

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
        SAFE_SYSCALL(mknod, path, kind2S_[kind], devno);
        break;
      case 1:
        SAFE_SYSCALL(mkdir, path, 0);
        break;
      case 5:
        SAFE_SYSCALL(symlink, maybe_linktarget, path);
        break;
      default:
        throw runtime_error("weird kind");
    }
    SAFE_SYSCALL(chmod, path, (mode_t)perms);
    SAFE_SYSCALL(lchown, path, (uid_t)uid, (gid_t)gid);
    if(kind == 0) {
      SAFE_SYSCALL(truncate, path, (off_t)size);
    }
    struct utimbuf tb;
    tb.actime = atime;
    tb.modtime = mtime;
    SAFE_SYSCALL(utime, path, &tb);
    if(xattr_val_idx.size() != xattr_name_idx.size()) {
      throw runtime_error("restore: xattr_name_idx and xattr_val_idx have differing sizes");
    }
    FOR(i, xattr_name_idx.size())
      SAFE_SYSCALL(lsetxattr, path,
          &_xattr_data[xattr_name_idx.size()],
          &_xattr_data[xattr_val_idx.size()],
          strlen(&_xattr_data[xattr_val_idx.size()]), 0);

  }

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

struct s_inode_metadata_hdr {
  char kind;
  ino_t ino;
  int uid, gid;
  size_t size;
  unsigned short perms;
  time_t atime, ctime, mtime;
} __attribute__((packed));

string serialise(const inode_metadata &md) {
  s_inode_metadata_hdr h;
  h.kind = md.kind;
  h.ino = md.ino;
  h.uid = md.uid;
  h.gid = md.gid;
  h.perms = md.perms;
  h.atime = md.atime;
  h.ctime = md.ctime;
  h.mtime = md.mtime;
  h.size = md.size;
  string ans((char *)&h, (char *)&h + sizeof(s_inode_metadata_hdr));
  if (h.kind == 2 || h.kind == 3) {
    ans += md.devno & 255;
    ans += md.devno >> 8 & 255;
  }
  string xattrs;
  FOR(i, md.nxattrs()) {
    xattrs += md.xattr_name(i);
    xattrs += '\0';
    xattrs += md.xattr_val(i);
    xattrs += '\0';
  }
  ans += length_prefixed(xattrs);
  return ans;
}

inode_metadata deserialise(const string &s, const string &xattrs) {
  const s_inode_metadata_hdr &h = *(s_inode_metadata_hdr*)&s[0];
  const char *cdr = &s[0] + sizeof(s_inode_metadata_hdr);
  inode_metadata md;
  md.kind = h.kind;
  md.ino = h.ino;
  md.uid = h.uid;
  md.gid = h.gid;
  md.perms = h.perms;
  md.atime = h.atime;
  md.ctime = h.ctime;
  md.mtime = h.mtime;
  md.size = h.size;
  if (h.kind == 2 || h.kind == 3) {
    md.devno = cdr[1] << 8 | cdr[0];
    cdr += 2;
  }

  md._xattr_data.resize(xattrs.size());
  memcpy(&md._xattr_data[0], &xattrs[0], xattrs.size());
  
  int start = 0;
  bool iskey = true;
  FOR(i, md._xattr_data.size()) {
    if(md._xattr_data[i] == '\0') {
      if(iskey) {
        md.xattr_name_idx.push_back(start);
      } else {
        md.xattr_val_idx.push_back(start);
      }
      start = i+1;
      iskey = ~iskey;
    }
  }
  return md;
}

static const int threads = 64;

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

// TODO:  If the fs supports it, use FIEMAP or FIBMAP to figure out the extents
// of a directory.  Use the first extent instead of the inode number.
struct dirtree_walker {
  mutex mu;
  multimap<int, function<void()> > q;
  condition_variable cv;
  int done;

  void pushit(int key, function<void()> f) {
    lock_guard<mutex> g(mu);
    q.insert(make_pair(key, f));
    cv.notify_one();
  }

  void processing_thread() {
    int lastino = 0;
    while (1) {
      function<void()> f;
      {
        unique_lock<mutex> lg(mu);
        while (!q.size()) {
          if (done) return;
          cv.wait(lg);
        }
        auto it = q.lower_bound(lastino);
        if (it == q.end()) it = q.begin();
        lastino = it->first;
        f = it->second;
        q.erase(it);
      }
      f();
    }
  }

  function<void(const string &, const inode_metadata &)> handler;

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
        if (md.kind == 1)
          pushit(ino,[name,this]{scan_directory(name);});
        handler(name, md);
      } catch (exception &e) {
        fprintf(stderr, "while processing %s: %s\n", name.c_str(), e.what());
        throw e;
      }
    }

    return 0;
  }

  dirtree_walker(const char *dt) {
    done = 0;
    pushit(0, [dt,this]{scan_directory(dt); return 0;});
  }

  void go() {
    vector<thread> vt;
    for (int i = 0; i < threads; i++)
      vt.push_back(thread([this](){processing_thread();}));
    done = 1;
    cv.notify_all();
    for (int i = 0; i < threads; i++)
      vt[i].join();
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

struct outputter {
  mutex mu;
  condition_variable qempty, qfull;
  queue<unique_ptr<pending_output> > q;
  int totsiz;
  atomic<int> done;

  outputter() {
    totsiz = 0;
    done = 0;
  }

  void push(unique_ptr<pending_output> po, size_t siz) {
    unique_lock<mutex> lg(mu);
    while (totsiz > (64<<20)) qfull.wait(lg);
    q.push(move(po));
    totsiz += siz;
    qempty.notify_all();
  }

  void go() {
    while (1) {
      unique_ptr<pending_output> po;
      vector<iovec> iov;
      { unique_lock<mutex> lg(mu);
        while (!q.size()) {
          if (done) return;
          qempty.wait(lg);
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
          fprintf(stderr, "%llx %lli\n", vec[i].iov_base, vec[i].iov_len);
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

struct data_grabber {
  mutex mu;
  unordered_map<ino_t, string> inode_canon;
  vector<pair<uint64_t, pair<string, vector<ffextent> > > > bigwork, smallwork;

  // mashed together two concerns here; fix.  note reuse of mu.
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

  multiset<pending_io> bigpend, smallpend;
  condition_variable bigcv, smallcv;
  int done;

  void doio(const pending_io &p) {
    char *_buf = new char[p.len + 4096];
    unique_ptr<char[]> argh(_buf);
    char *buf = _buf;
    buf += 4096 - ((intptr_t)buf & 4095);
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
    if (0)
    fprintf(stderr, "asked to read %i bytes from %s starting at %i\n",
        (int)p.len, p.file.c_str(), (int)p.off);
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
    hdr += ll2string(p.off);
    hdr += int2string(fub-buf);
    enqueue_datapkt(hdr, _buf, buf-_buf, fub-buf);
  }

  void consumer(multiset<pending_io> &pend, condition_variable &cv) {
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

  void doit() {
    static const int grab_nthread = 16;
    static const int small_grab_nthread = 64;
    vector<thread> vt;
    FOR(i, grab_nthread)
      vt.push_back(thread([this](){consumer(bigpend, bigcv);}));
    FOR(i, small_grab_nthread)
      vt.push_back(thread([this](){consumer(smallpend, smallcv);}));
    FOR(i, bigwork.size())
      FOR(j, bigwork[i].second.second.size()) {
        unique_lock<mutex> lg(mu);
        const string &foo = bigwork[i].second.first;
        bigpend.insert(pending_io(foo, bigwork[i].second.second[j]));
        bigcv.notify_one();
      }
    sort(smallwork.begin(), smallwork.end());
    FOR(i, smallwork.size())
      FOR(j, smallwork[i].second.second.size()) {
        unique_lock<mutex> lg(mu);
        const string &foo = smallwork[i].second.first;
        ffextent &e = smallwork[i].second.second[j];
        if (e.len > 65536) {
          bigpend.insert(pending_io(foo, e));
          bigcv.notify_one();
        } else {
          smallpend.insert(pending_io(foo, e));
          smallcv.notify_one();
        }
      }
    done = 1;
    bigcv.notify_all();
    smallcv.notify_all();
    FOR(i, vt.size()) vt[i].join();
  }

  void coalesce() {
    // TODO
  }

  int add(const string &name, const inode_metadata &md) {
    { lock_guard<mutex> lg(mu);
      if (inode_canon.count(md.ino)) {
        // hard links
        string block = length_prefixed(name) + "\007"
            + length_prefixed(inode_canon[md.ino]);
        enqueue_block(block);
        return 1;
      }
      inode_canon[md.ino] = name;
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
      if (totlen == 0) {
        return 0;
      }
      if (totlen > (32<<20)) {
        lock_guard<mutex> lg(mu);
        bigwork.push_back(make_pair(ext.extents[0].blk,
            make_pair(name, ext.extents)));
      } else {
        lock_guard<mutex> lg(mu);
        smallwork.push_back(make_pair(ext.extents[0].blk,
            make_pair(name, ext.extents)));
      }
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
      enqueue_block(prefix + serialise(md));
    } break;
    case 5: {
      string foo = prefix + serialise(md);
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
        enqueue_block(prefix + serialise(md));
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
  int len;
  FREAD_EOF(&len, 1, 4);
  string s(len, '\0');
  FREAD(&s[0], 1, len);
  return s;
}

inode_metadata get_inode_md(char kind, FILE * f) {
  ungetc(kind, f);
  char bfr1[sizeof(s_inode_metadata_hdr) + 6];
  char * p = bfr1;
  FREAD(p, sizeof(s_inode_metadata_hdr), 1);
  p += sizeof(s_inode_metadata_hdr);
  if(kind == 2 || kind == 3) {
    FREAD(p, 1, 2);
    p += 2;
  }

  string xattrs = read_lenprestring(f);
  string allbfr = string(bfr1, p);

  return deserialise(allbfr, xattrs);
}

bool dry_run = false;

void restore_data(string filename, FILE *f) {
  unsigned long long offset;
  FREAD(&offset, 8, 1);
  int datalen;
  FREAD(&datalen, 4, 1);

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
      char buf[65536];
      int zzz = min(65536, datalen);
      int len = fread(buf, 1, zzz, f);
      if (len != zzz) {
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
      char buf[65536];
      int zzz = min(65536, datalen);
      int len = fread(buf, 1, zzz, f);
      fprintf(stderr, "I want to write %i bytes; %i remain.\n", len, datalen);
      datalen -= len;
    }
  }
}

vector<pair<string, utimbuf> > time_fixup_list;

void fixup_times() {
  FOR(i, time_fixup_list.size())
    if (utime(time_fixup_list[i].first.c_str(), &time_fixup_list[i].second) < 0)
      fprintf(stderr, "warning: couldn't fixup times for %s: %s\n",
          time_fixup_list[i].first.c_str(), strerror(errno));
}

void restore(FILE *f) {
  while (1) {
    int c;
    string from = read_lenprestring(f);
    switch ((c = getc(f))) {
      case 0: case 1: {
        inode_metadata md = get_inode_md(c, f);
        md.restore(from.c_str(), 0);
        utimbuf tb;
        tb.actime = md.atime;
        tb.modtime = md.mtime;
        time_fixup_list.push_back(make_pair(from, tb));
      } break;
      case 2: case 3: case 4: case 6: {
        inode_metadata md = get_inode_md(c, f);
        md.restore(from.c_str(), 0);
      } break;
      case 5: {
        inode_metadata md = get_inode_md(c, f);
        string to = read_lenprestring(f);
        md.restore(from.c_str(), to.c_str());
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
  if (!unpack) {
    thread out([](){output.go();});
    dirtree_walker w(argv[argno]);
    w.handler = handle_dent;
    w.go();
    grab.coalesce();
    grab.doit();
    output.done = 1;
    output.qempty.notify_all();
    out.join();
  } else {
    try {
      restore(stdin);
    } catch (eof_exception &e) {}
    fixup_times();
  }
}
