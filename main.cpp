#include "File.h"
#include "BinaryLog.h"

#include <unistd.h>
#include <iostream>
#include <cstdlib>

using namespace std;

int main() try
{
   BinaryLog<int, int, 1000> bf{"/tmp/baa.txt", false, false};

   std::string sep = "";
   for(int i = 0; i < 10; ++i)
   {
      cout << sep << bf[i];
      sep = ", ";
   }

   cout << "\n";

   bf[0] = rand();
   bf[1] = rand();
   bf[2] = rand();
   bf[10] = rand();
   bf[999] = rand();

   return 1;

   /*
   File f{"/tmp/foo.txt", File::RDWR, 0644};

   {
      cout << "Going to get EX lock\n";

      if( auto&& L = f.ExclusiveLock() )
      {
         cout << "EX lock - " << L.Held() << "\n";

         f.Write("abcd\n");
         f.Pwrite("def", 0);

         f.Seek(0, File::SET);
         cout << f.Read(4) << endl;

         sleep(30);
      }
   }

   cout << "LR\n";
   sleep(30);
   */
}
catch(const std::exception& e)
{
   cout << e.what() << endl;
}
