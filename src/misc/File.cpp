#include "File.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <unistd.h>

#include <stdexcept>
#include <cerrno>
#include <cstring>

void File::Truncate(off64_t NewSz)
{
   while(true)
   {
      errno = 0;
      int r = ::ftruncate(m_fd, NewSz);
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error truncating file: '" + m_pathname + "' error - " + strerror(errno));
      }
      else
         break;
   }
}

bool File::Exists(const std::string& pathname)
{
   while(true)
   {
      errno = 0;
      struct stat64 buf;
      int r = ::stat64(pathname.c_str(), &buf);
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            return false;
      }
      else
      {
         return true;
      }
   }
}

off64_t File::Size() const
{
   while(true)
   {
      errno = 0;
      struct stat64 buf;
      int r = ::fstat64(m_fd, &buf);
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error stating file: '" + m_pathname + "' error - " + strerror(errno));
      }
      else
      {
         return buf.st_size;
      }
   }
}

void File::Rename(const std::string& newpath)
{
   while(true)
   {
      errno = 0;
      int r = ::rename(m_pathname.c_str(), newpath.c_str());
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error renaming file: '" + m_pathname + "' to '" + newpath + "' error - " + strerror(errno));
      }
      else
      {
         m_pathname = newpath;
         break;
      }
   }
}

void File::Close() noexcept
{
   if(Valid())
      ::close(m_fd);

   m_fd = -1;
}

void File::Seek(off64_t offset, WhenceOpt whence)
{
   int lseek_whence = 0;
   switch(whence)
   {
      case SET :
         lseek_whence = SEEK_SET;
         break;
      case END :
         lseek_whence = SEEK_END;
         break;
      case CUR :
         lseek_whence = SEEK_CUR;
         break;
   }

   while(true)
   {
      errno = 0;
      int r = ::lseek64(m_fd, offset, lseek_whence);
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error seeking into file: '" + m_pathname + "' error - " + strerror(errno));
      }
      else
      {
         break;
      }
   }
}

std::size_t File::RawRead(void* buf, std::size_t sz, bool full)
{
   std::size_t c = 0;
   while(true)
   {
      errno = 0;
      int r = ::read(m_fd, reinterpret_cast<char*>(buf) + c, sz - c);
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error reading file: '" + m_pathname + "' error - " + strerror(errno));
      }
      else
      {
         c += r;

         if(c == sz)
            break;

         if(r == 0)
         {
            if(full)
               throw std::runtime_error("error reading file: '" + m_pathname + "' incompelt read");

            break;
         }
      }
   }

   return c;
}

std::size_t File::RawWrite(const void* buf, std::size_t sz, bool full)
{
   std::size_t c = 0;
   while(true)
   {
      errno = 0;
      int r = ::write(m_fd, reinterpret_cast<const char*>(buf) + c, sz - c);
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error writing file: '" + m_pathname + "' error - " + strerror(errno));
      }
      else
      {
         c += r;

         if(c == sz)
            break;

         if(r == 0)
         {
            if(full)
               throw std::runtime_error("error writing file: '" + m_pathname + "' incomplet write");

            break;
         }
      }
   }

   return c;
}

std::size_t File::RawPread(void* buf, std::size_t sz, off64_t where, bool full) const
{
   std::size_t c = 0;
   while(true)
   {
      errno = 0;
      int r = ::pread64(m_fd, reinterpret_cast<char*>(buf) + c, sz - c, where + c);
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error preading file: '" + m_pathname + "' error - " + strerror(errno));
      }
      else
      {
         c += r;

         if(c == sz)
            break;

         if(r == 0)
         {
            if(full)
               throw std::runtime_error("error preading file: '" + m_pathname + "' incompelt read");

            break;
         }
      }
   }

   return c;
}

std::size_t File::RawPwrite(const void* buf, std::size_t sz, off64_t where, bool full)
{
   std::size_t c = 0;
   while(true)
   {
      errno = 0;
      int r = ::pwrite64(m_fd, reinterpret_cast<const char*>(buf) + c, sz - c, where + c);
      if(r == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error pwriting file: '" + m_pathname + "' error - " + strerror(errno));
      }
      else
      {
         c += r;

         if(c == sz)
            break;

         if(r == 0)
         {
            if(full)
               throw std::runtime_error("error pwriting file: '" + m_pathname + "' incomplet write");

            break;
         }
      }
   }

   return c;
}

int File::ScopedLockGuard::LockWrapper(int fd, const std::string& pathname, bool lock, bool exclusive, bool non_blocking)
{
   int operation = (lock ? ((exclusive ? LOCK_EX : LOCK_SH) | (non_blocking ? LOCK_NB : 0)) : LOCK_UN);

   while(true)
   {
      errno = 0;
      int x = ::flock(fd, operation); // requires Linux >= 2.6.12
      if(x == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error operating locking on file: '" + pathname + "' error - " + strerror(errno));

         if((operation & LOCK_NB) == LOCK_NB)
            return -1; // return early without looping if NB is set
      }
      else
         return fd;
   }
}

void File::OpenWrapper(const std::string& pathname, OpenFlags flags, bool create, int permissions)
{
   int open_flags = O_LARGEFILE | (create ? O_CREAT : 0);

   open_flags |= (static_cast<int>(flags) & (READ | WRITE))  == (READ | WRITE) ? O_RDWR   : 0;
   open_flags |= (static_cast<int>(flags) & (READ | WRITE))  == READ           ? O_RDONLY : 0;
   open_flags |= (static_cast<int>(flags) & (READ | WRITE))  == WRITE          ? O_WRONLY : 0;
   open_flags |= (static_cast<int>(flags) & APPEND)          == APPEND         ? O_APPEND : 0;
   open_flags |= (static_cast<int>(flags) & EXCL)            == EXCL           ? (create ? O_EXCL : 0) : 0;

   while(true)
   {
      errno = 0;
      int fd = ::open(pathname.c_str(), open_flags, permissions);

      if(fd == -1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error opening file: '" + pathname + "' error - " + strerror(errno));
      }
      else
      {
         m_fd = fd;
         m_flags = flags;
         m_pathname = pathname;
         break;
      }
   }
}


void File::ScopedMapGuard::Synchronize(bool block, bool invalidate)
{
   if(Valid())
   {
      int msync_flags = (block ? MS_SYNC : MS_ASYNC) | (invalidate ? MS_INVALIDATE : 0);

      ::msync(m_map_addr, m_map_length, msync_flags);
   }
}

void File::ScopedMapGuard::Release() noexcept
{
   if(Valid())
   {
      ::munmap(m_map_addr, m_map_length);

      m_map_addr = nullptr;
   }
}

void File::ScopedMapGuard::MmapWrapper(int fd, const std::string& pathname, OpenFlags flags, off64_t offset, std::size_t length)
{
   int map_prot = 0;
   map_prot |= (static_cast<int>(flags) & READ)  == READ  ? PROT_READ  : 0;
   map_prot |= (static_cast<int>(flags) & WRITE) == WRITE ? PROT_WRITE : 0;

   long page_size = sysconf(_SC_PAGE_SIZE);

   off64_t     map_offset = (offset / page_size) * page_size;
   std::size_t map_length = length + offset - map_offset;

   while(true)
   {
      errno = 0;
      void* map_addr = ::mmap64(nullptr, map_length, map_prot, MAP_SHARED, fd, map_offset);
      if(map_addr == (void*) - 1)
      {
         if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            throw std::runtime_error("error mmaping file: '" + pathname + "' error - " + strerror(errno));
      }
      else
      {
         m_map_length = map_length;
         m_map_addr_offset = offset - map_offset;
         m_map_addr = map_addr;
         break;
      }
   }
}
