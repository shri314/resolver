#include <string>
#include <cassert>
#include <stdexcept>

template<typename HeaderT, typename DataT, uint64_t CapacityV>
class BinaryLog
{
   public:
      BinaryLog(const std::string& file, bool readonly, bool lock)
      {
         m_readonly = readonly;

         if(!m_readonly)
         {
            if(!File::Exists(file))
            {
               File tmp(file + ".tmp", File::RDWR, 0644);

               if(auto && L = tmp.ExclusiveLock())
               {
                  if(!File::Exists(file))
                  {
                     tmp.Truncate(sizeof(FileData));

                     tmp.Pwrite(HeaderT{}, 0);

                     tmp.Rename(file);
                  }
               }
            }
         }

         File tmp(file, m_readonly ? File::READ : File::RDWR);

         if(sizeof(FileData) != tmp.Size())
            throw std::runtime_error("Invalid or corrupt log - '" + tmp.Name() + "'");

         m_mapping = tmp.LoadMap();

         if(lock)
            m_guard = Lock(tmp);
      }

      BinaryLog(BinaryLog&& rhs) = delete;
      void operator=(BinaryLog&&) = delete;

      BinaryLog(const BinaryLog&) = delete;
      void operator=(const BinaryLog&) = delete;

      bool Valid() const
      {
         return m_mapping.Valid();
      }

      HeaderT& Header()
      {
         assert(!m_readonly && m_mapping.Valid());

         return m_mapping.Get<FileData>()->m_header;
      }

      const HeaderT& Header() const
      {
         assert(m_mapping.Valid());

         return m_mapping.Get<FileData>()->m_header;
      }

      DataT& operator[](std::size_t index)
      {
         assert(!m_readonly && index < CapacityV && index >= 0 && m_mapping.Valid());

         return m_mapping.Get<FileData>()->m_entries[index];
      }

      const DataT& operator[](std::size_t index) const
      {
         assert(index < CapacityV && index >= 0 && m_mapping.Valid());

         return m_mapping.Get<FileData>()->m_entries[index];
      }

   private:
      File::ScopedLockGuard Lock(File& file)
      {
         if(m_readonly)
            return file.SharedLock();
         else
            return file.ExclusiveLock();
      }

   private:
      struct FileData
      {
         HeaderT m_header = {};
         DataT m_entries[CapacityV] = {};
      };

      bool m_readonly = true;
      File::ScopedLockGuard m_guard;
      File::ScopedMapGuard m_mapping;
};
