#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
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
#include <atomic>
#include <queue>
#include <semaphore.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <sys/ioctl.h>
#include <fcntl.h>
using namespace std;

#define FOR(i,n) for (int i=0;i<n;i++)

struct semaphore {
  sem_t sem;
  semaphore() { sem_init(&sem, 0, 0); }

  void wait() {
    while (1) {
      int st = sem_wait(&sem);
      if (st && errno == EINTR) continue;
      else if (st) {
        perror("sem_wait");
        abort();
      } else break;
    }
  }

  void post() {
    top:;
    int st = sem_post(&sem);
    if (st && errno == EOVERFLOW) { usleep(1000); goto top; }
    if (st) { perror("sem_post"); abort(); }
  }

  int get() { int k; sem_getvalue(&sem, &k); return k; }
};

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

struct ffextent {
  ffextent(bool a, bool l, uint64_t o, uint64_t le)
    : aligned(a), last(l), off(o), len(le) { };
  bool aligned, last;
  uint64_t off, len;
};

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
      struct fiemap * exts = (struct fiemap *)
        alloca(sizeof(struct fiemap) + sizeof(struct fiemap_extent) * extinfo.fm_mapped_extents);
      memset(exts, 0, sizeof(struct fiemap));

      exts->fm_start = 0;
      exts->fm_length = ~0;
      exts->fm_extent_count = extinfo.fm_mapped_extents;

      while(ioctl(fd, FS_IOC_FIEMAP, exts) < 0) {
        if(errno != EINTR)
          throw runtime_error(strprintf("FS_IOC_FIEMAP failed: %s", strerror(errno)));
      }
      if(!(exts->fm_extents[exts->fm_mapped_extents-1].fe_flags & FIEMAP_EXTENT_LAST))
        continue;

      extents.reserve(exts->fm_mapped_extents);
      for(uint32_t i = 0; i < exts->fm_mapped_extents; i++) {
        struct fiemap_extent * e = exts->fm_extents + i;
        if(e->fe_flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC
            | FIEMAP_EXTENT_ENCODED | FIEMAP_EXTENT_DATA_ENCRYPTED
            | FIEMAP_EXTENT_UNWRITTEN))
        {
          throw runtime_error(strprintf("bogus extent: %u", e->fe_flags));
        }
        extents.push_back(
            ffextent(!(e->fe_flags & FIEMAP_EXTENT_NOT_ALIGNED),
              e->fe_flags & FIEMAP_EXTENT_LAST,
              e->fe_physical,
              e->fe_length));
      }
      break;
    }
  }
};


struct inode_metadata {
  int kind; // regular, device, etc.
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
    perms = st.st_mode & 0xffff;
    size = st.st_size;
    devno = st.st_dev;
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
    //FOR(i, _xattr_data.size()) printf("%hhx ", _xattr_data[i]); printf("\n");
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
};

static const int threads = 64;

struct dirtree_walker {
  mutex mu;
  multimap<int, function<void()> > q;
  semaphore qsize;
  atomic<int> energy;

  void pushit(int key, function<void()> f) {
    lock_guard<mutex> g(mu);
    q.insert(make_pair(key, f));
    qsize.post();
    ++energy;
  }

  void processing_thread() {
    int lastino = 0;
    while (energy != 0) {
      qsize.wait();
      function<void()> f;
      {
        lock_guard<mutex> g(mu);
        auto it = q.lower_bound(lastino);
        if (it == q.end()) it = q.begin();
        if (it == q.end()) { fprintf(stderr, "underfull queue\n"); break; }
        lastino = it->first;
        f = it->second;
        q.erase(it);
      }
      f();
      --energy;
    }

    pushit(0, [](){return 0;});
  }

  void handle_unk(string s, ino_t myino) {
    if (scan_directory(s, myino)) handle_file(s, myino);
  }

  int handle_file(string s, ino_t myino) {
    return 0;
  }

  struct dir_raii {
    DIR *d;
    dir_raii(DIR *d) : d(d) {}
    ~dir_raii() { closedir(d); }
  };

  int scan_directory(string dir, ino_t myino) {
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
        if (md.kind == 1) {
          printf("mkdir %s\n", name.c_str());
          pushit(ino,[name,ino,this]{scan_directory(name,ino);});
        } else if (md.kind == 2) {
          printf("nod c %s %i\n", name.c_str(), md.devno);
        } else if (md.kind == 3) {
          printf("nod b %s %i\n", name.c_str(), md.devno);
        } else if (md.kind == 4) {
          printf("fifo %s\n", name.c_str());
        } else if (md.kind == 5) {
          char buf[8192];
          while (1) {
            int len = readlink(name.c_str(), buf, 8190);
            if (len < 0) {
              if (errno == EINTR) continue;
              throw runtime_error(strprintf("readlink(%s): %s", name.c_str(),
                  strerror(errno)));
            }
            buf[len] = 0;
            break;
          }
          printf("lnk %s %s\n", name.c_str(), buf);
        } else if (md.kind == 6) {
          printf("sock %s\n", name.c_str());
        } else if (md.kind == 0) {
          printf("file %s\n", name.c_str());
        } else throw runtime_error(strprintf("weird kind %i", md.kind));
      } catch (exception &e) {
        fprintf(stderr, "while processing %s: %s\n", name.c_str(), e.what());
        throw e;
      }
    }

    return 0;
  }

  dirtree_walker(const char *dt) {
    pushit(0, [dt,this]{scan_directory(dt,-1); return 0;});
    energy = 1;
  }

  void go() {
    vector<thread> vt;
    for (int i = 0; i < threads; i++)
      vt.push_back(thread([this](){processing_thread();}));
    for (int i = 0; i < threads; i++)
      vt[i].join();
  }
};

int main(int argc, char **argv) {
  dirtree_walker w(argv[1]);
  w.go();
}
