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
#include <condition_variable>
#include <atomic>
#include <queue>
#include <semaphore.h>
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
  int nxattrs() const { return xattr_name_idx.size(); }
};

struct s_inode_metadata_hdr {
  char kind;
  ino_t ino;
  int uid, gid;
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
  string ans((char *)&h, (char *)(&h+1));
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
  unsigned int siz = xattrs.size();
  FOR(i, 4) ans += siz & 255, siz >>= 8;
  return ans + xattrs;
}

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

  function<void(const string &, const inode_metadata &)> handler;
  
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
        if (md.kind == 1)
          pushit(ino,[name,ino,this]{scan_directory(name,ino);});
        handler(name, md);
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

struct outputter {
  mutex mu;
  condition_variable qempty, qfull;
  queue<string> q;
  int totsiz;
  int done;

  outputter() {
    totsiz = 0;
    done = 0;
  }

  void push(const string &s) {
    unique_lock<mutex> lg(mu);
    while (totsiz > (64<<20)) qfull.wait(lg);
    q.push(s);
    totsiz += s.size();
    qempty.notify_all();
  }

  void go() {
    while (1) {
      string s;
      { unique_lock<mutex> lg(mu);
        while (!q.size()) {
          qempty.wait(lg);
          if (done) return;
        }
        s = move(q.front());
        q.pop();
        totsiz -= s.size();
      }
      dowrite(&s[0], s.size());
      qfull.notify_all();
    }
  }

  static void dowrite(const char *p, int sz) {
    while (sz) {
      int len = write(1, p, sz);
      if (len < 0) {
        if (errno == EINTR) continue;
        else throw runtime_error(strprintf("outputter couldn't output: %s",
            strerror(errno)));
      }
      p += len;
      sz -= len;
    }
  }
} output;

void enqueue_block(const string &s) {
  output.push(s);
}

void handle_dent(const string &name, const inode_metadata &md) {
  switch (md.kind) {
    case 1: case 2: case 3: case 4: case 6: {
      enqueue_block(serialise(md));
    } break;
    case 5: {
      string foo = serialise(md);
      char buf[8192];
      while (1) {
        int len = readlink(name.c_str(), buf, 8192);
        if (len < 0) {
          if (errno == EINTR) continue;
          throw runtime_error(strprintf("readlink(%s): %s", name.c_str(),
              strerror(errno)));
        }
        int k = len;
        FOR(i, 4) foo += k, k >>= 8;
        foo += string(buf, buf + len);
        break;
      }
      enqueue_block(foo);
    } break;
    case 0: {
      enqueue_block(serialise(md));
    } break;
    default: throw runtime_error(strprintf("weird kind %i", md.kind));
  }
}

int main(int argc, char **argv) {
  thread out([](){output.go();});
  dirtree_walker w(argv[1]);
  w.handler = handle_dent;
  w.go();
  output.done = 1;
  output.qempty.notify_all();
  out.join();
}
