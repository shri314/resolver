#ifndef FILE_H__e9345708_04ee_4c31_9cb5_e5cdfaa82d79
#define FILE_H__e9345708_04ee_4c31_9cb5_e5cdfaa82d79

#include <type_traits>
#include <utility>
#include <string>

class File
{
   public:
      enum OpenFlags
      {
         NONE    = 0,
         WRITE   = (1 << 0),
         READ    = (1 << 1),
         RDWR    = READ | WRITE,
         APPEND  = (1 << 2) | WRITE,
         EXCL    = (1 << 3),
      };

      enum WhenceOpt
      {
         SET = 0,
         END = 1,
         CUR = 2,
      };

      friend OpenFlags operator|(OpenFlags lhs, OpenFlags rhs)
      {
         return static_cast<OpenFlags>(static_cast<int>(lhs) | static_cast<int>(rhs));
      }

      File(const std::string& pathname, OpenFlags flags, int permissions)
      {
         OpenWrapper(pathname, flags, /*create = */true, permissions);
      }

      File(const std::string& pathname, OpenFlags flags)
      {
         OpenWrapper(pathname, flags, /*create = */false, 0);
      }

      File(File&& rhs) noexcept
         : m_pathname(std::move(rhs.m_pathname))
         , m_flags(std::move(rhs.m_flags))
         , m_fd(std::move(rhs.m_fd))
      {
         rhs.m_fd = -1;
      }

      File() noexcept
      {
      }

      File(const File&) = delete;
      void operator=(const File& rhs) = delete;

      File& operator=(File&& rhs) noexcept
      {
         Close();

         m_pathname = std::move(rhs.m_pathname);
         m_flags = std::move(rhs.m_flags);
         m_fd = std::move(rhs.m_fd);
         
         rhs.m_fd = -1;

         return *this;
      }

      void Truncate(off64_t NewSz);

      std::string Name() const noexcept
      {
         return m_pathname;
      }

      bool Valid() const noexcept
      {
         return m_fd != -1;
      }

      static bool Exists(const std::string& pathname);

      off64_t Size() const;

      void Rename(const std::string& newpath);

      void Close() noexcept;

      ~File() noexcept
      {
         Close();
      }

      int FileHandle() const noexcept
      {
         return m_fd;
      }

      void Seek(off64_t offset, WhenceOpt whence);

      template<typename T>
      typename std::enable_if< std::is_trivially_copyable<T>::value, T >::type
      Read()
      {
         T buf;
         RawRead(&buf, sizeof buf, true);

         return buf;
      }

      template<typename T>
      typename std::enable_if< std::is_trivially_copyable<T>::value, T >::type
      Pread(off64_t where) const
      {
         T buf;
         RawPread(&buf, sizeof buf, where, true);

         return buf;
      }

      std::string Read(std::size_t sz)
      {
         std::string buf;
         buf.resize(sz);

         RawRead(&buf[0], buf.size(), true);

         return buf;
      }

      std::string Pread(std::size_t sz, off64_t where) const
      {
         std::string buf;
         buf.resize(sz);

         RawPread(&buf[0], buf.size(), where, true);

         return buf;
      }

      std::string ReadSome(std::size_t sz)
      {
         std::string buf;
         buf.resize(sz);
         buf.resize(RawRead(&buf[0], buf.size(), false));

         return buf;
      }

      std::string PreadSome(std::size_t sz, off64_t where) const
      {
         std::string buf;
         buf.resize(sz);
         buf.resize(RawPread(&buf[0], buf.size(), where, false));

         return buf;
      }

      template<typename T>
      typename std::enable_if< std::is_trivially_copyable<T>::value, void >::type
      Write(const T& buf)
      {
         RawWrite(&buf, sizeof buf, true);
      }

      template<typename T>
      typename std::enable_if< std::is_trivially_copyable<T>::value, void >::type
      Pwrite(const T& buf, off64_t where)
      {
         RawPwrite(&buf, sizeof buf, where, true);
      }

      void Write(const std::string& buf)
      {
         RawWrite(&buf[0], buf.size(), true);
      }

      void Write(const std::string& buf, off64_t where)
      {
         RawPwrite(&buf[0], buf.size(), where, true);
      }

      std::size_t WriteSome(const std::string& buf)
      {
         return RawWrite(&buf[0], buf.size(), false);
      }

      std::size_t PwriteSome(const std::string& buf, off64_t where)
      {
         return RawPwrite(&buf[0], buf.size(), where, false);
      }

      std::size_t RawRead(void* buf, std::size_t sz, bool full);
      std::size_t RawWrite(const void* buf, std::size_t sz, bool full);
      std::size_t RawPread(void* buf, std::size_t sz, off64_t where, bool full) const;
      std::size_t RawPwrite(const void* buf, std::size_t sz, off64_t where, bool full);

      class ScopedLockGuard
      {
         private:
            enum LockOptions
            {
               BLOCKING,
               NON_BLOCKING,
            };

            enum LockType
            {
               EXCLUSIVE_LOCK,
               SHARED_LOCK,
            };

            friend class File;

         private:
            ScopedLockGuard(int fd, const std::string& pathname, LockOptions lo, LockType lt)
               : m_pathname(pathname)
            {
               m_fd = LockWrapper(fd, m_pathname, /*lock = */true, /*exclusive = */ (lt == EXCLUSIVE_LOCK), /*non_blocking = */ (lo == NON_BLOCKING) );
            }

            ScopedLockGuard(const ScopedLockGuard&) = delete;
            void operator=(const ScopedLockGuard&) = delete;

         public:
            ScopedLockGuard() noexcept
            {
            }

            ScopedLockGuard(ScopedLockGuard&& rhs) noexcept
               : m_pathname(std::move(rhs.m_pathname))
               , m_fd(std::move(rhs.m_fd))
            {
               rhs.m_fd = -1;
            }

            ScopedLockGuard& operator=(ScopedLockGuard&& rhs) noexcept
            {
               Release();

               m_pathname = std::move(rhs.m_pathname);
               m_fd = std::move(rhs.m_fd);
               
               rhs.m_fd = -1;

               return *this;
            }

            bool Held() const noexcept
            {
               return m_fd != -1;
            }

            explicit operator bool() const noexcept
            {
               return Held();
            }

            void Release() noexcept
            {
               if(Held())
                  m_fd = LockWrapper(m_fd, m_pathname, /*lock = */false, /*exclusive = */false, /*non_blocking = */false);
            }

            ~ScopedLockGuard() noexcept
            {
               Release();
            }

         private:
            static int LockWrapper(int fd, const std::string& pathname, bool lock, bool exclusive, bool non_blocking);

         private:
            std::string m_pathname;
            int m_fd = -1;
      };

      ScopedLockGuard ExclusiveLock(bool block = true)
      {
         return ScopedLockGuard(m_fd, m_pathname, block ? ScopedLockGuard::BLOCKING : ScopedLockGuard::NON_BLOCKING, ScopedLockGuard::EXCLUSIVE_LOCK);
      }

      ScopedLockGuard SharedLock(bool block = true)
      {
         return ScopedLockGuard(m_fd, m_pathname, block ? ScopedLockGuard::BLOCKING : ScopedLockGuard::NON_BLOCKING, ScopedLockGuard::SHARED_LOCK);
      }

      class ScopedMapGuard
      {
         private:
               ScopedMapGuard(int fd, const std::string& pathname, OpenFlags flags, off64_t offset, std::size_t length)
               {
                  MmapWrapper(fd, pathname, flags, offset, length);
               }

               ScopedMapGuard(const ScopedMapGuard&) = delete;
               void operator=(const ScopedMapGuard&) = delete;
               
               friend class File;

         public:
               ScopedMapGuard() noexcept
               {
               }

               ScopedMapGuard(ScopedMapGuard&& rhs) noexcept
                  : m_map_addr_offset( std::move(rhs.m_map_addr_offset) )
                  , m_map_length( std::move(rhs.m_map_length) )
                  , m_map_addr( std::move(rhs.m_map_addr) )
               {
                  rhs.m_map_addr = nullptr;
               }

               ScopedMapGuard& operator=(ScopedMapGuard&& rhs) noexcept
               {
                  Release();

                  m_map_addr_offset = std::move(rhs.m_map_addr_offset);
                  m_map_length = std::move(rhs.m_map_length);
                  m_map_addr = std::move(rhs.m_map_addr);

                  rhs.m_map_addr = nullptr;

                  return *this;
               }

               template<class T>
               T* Get() noexcept
               {
                  if(Valid())
                     return reinterpret_cast<T*>( reinterpret_cast<char*>(m_map_addr) + m_map_addr_offset );
                  else
                     return nullptr;
               }

               template<class T>
               const T* Get() const noexcept
               {
                  if(Valid())
                     return reinterpret_cast<const T*>( reinterpret_cast<const char*>(m_map_addr) + m_map_addr_offset );
                  else
                     return nullptr;
               }

               std::size_t Size() const noexcept
               {
                  return m_map_length;
               }

               bool Valid() const noexcept
               {
                  return m_map_addr != nullptr;
               }

               explicit operator bool() const noexcept
               {
                  return Valid();
               }

               void Synchronize(bool block, bool invalidate);

               void Release() noexcept;

               ~ScopedMapGuard() noexcept
               {
                  Release();
               }

         private:
               void MmapWrapper(int fd, const std::string& pathname, OpenFlags flags, off64_t offset, std::size_t length);

         private:
               size_t m_map_addr_offset = 0;
               size_t m_map_length = 0;
               void* m_map_addr = nullptr;
      };

      ScopedMapGuard LoadMap()
      {
         return ScopedMapGuard(m_fd, m_pathname, m_flags, 0, Size());
      }

   private:
      void OpenWrapper(const std::string& pathname, OpenFlags flags, bool create, int permissions);

   private:
      std::string m_pathname;
      OpenFlags m_flags = NONE;
      int m_fd = -1;
};

#endif
