#include <iostream>

struct Lifter
{
};

template<class LExpr, class RExpr, class BinOp>
struct MyExpr
{
      MyExpr(LExpr le, RExpr re, BinOp bop, std::string sbop)
         : m_le{le}
         , m_re{re}
         , m_bop(bop)
         , m_sbop(sbop)
      {
      }

      auto value() const
      {
         return m_bop( m_le.value(), m_re.value() );
      }

      void print() const
      {
         m_le.print();
         std::cout << m_sbop;
         m_re.print();
      }

   private:
      LExpr m_le;
      RExpr m_re;
      BinOp m_bop;
      std::string m_sbop;
};

template<class RawV>
struct MyExpr<RawV, void, void>
{
      MyExpr(RawV r)
         : m_r{r}
      {
      }

      auto value() const
      {
         return m_r;
      }

      bool print() const
      {
         std::cout << "'" << m_r << "'";
      }

   private:
      RawV m_r;
};

/// OPERATORS

template<class T>
MyExpr<T, void, void> operator+ (Lifter, T a)
{
   return MyExpr<T, void, void> {a};
}

template<class LE, class RE, class Bop, class RawR>
auto operator<( MyExpr<LE, RE, Bop> lbe, RawR r)
{
   auto bop = [](auto a, auto b) { return a < b; };

   return MyExpr< MyExpr<LE, RE, Bop>, MyExpr<RawR, void, void>, decltype(bop) > { lbe, MyExpr<RawR, void, void>{r}, bop, " >= " };
}

template<class LE, class RE, class Bop, class RawR>
auto operator<=( MyExpr<LE, RE, Bop> lbe, RawR r)
{
   auto bop = [](auto a, auto b) { return a <= b; };

   return MyExpr< MyExpr<LE, RE, Bop>, MyExpr<RawR, void, void>, decltype(bop) > { lbe, MyExpr<RawR, void, void>{r}, bop, " > " };
}

template<class LE, class RE, class Bop, class RawR>
auto operator>=( MyExpr<LE, RE, Bop> lbe, RawR r)
{
   auto bop = [](auto a, auto b) { return a >= b; };

   return MyExpr< MyExpr<LE, RE, Bop>, MyExpr<RawR, void, void>, decltype(bop) > { lbe, MyExpr<RawR, void, void>{r}, bop, " < " };
}

template<class LE, class RE, class Bop, class RawR>
auto operator>( MyExpr<LE, RE, Bop> lbe, RawR r)
{
   auto bop = [](auto a, auto b) { return a > b; };

   return MyExpr< MyExpr<LE, RE, Bop>, MyExpr<RawR, void, void>, decltype(bop) > { lbe, MyExpr<RawR, void, void>{r}, bop, " <= " };
}

template<class LE, class RE, class Bop, class RawR>
auto operator==( MyExpr<LE, RE, Bop> lbe, RawR r)
{
   auto bop = [](auto a, auto b) { return a == b; };

   return MyExpr< MyExpr<LE, RE, Bop>, MyExpr<RawR, void, void>, decltype(bop) > { lbe, MyExpr<RawR, void, void>{r}, bop, " != " };
}

template<class LE, class RE, class Bop, class RawR>
auto operator+(MyExpr<LE, RE, Bop> l, RawR r)
{
   auto bop = [](auto a, auto b) { return a + b; };

   return MyExpr< MyExpr<LE, RE, Bop>, MyExpr<RawR, void, void>, decltype(bop) > { l, MyExpr<RawR, void, void>{r}, bop, " + " };
}

template<class LE, class RE, class Bop, class RawR>
auto operator-(MyExpr<LE, RE, Bop> l, RawR r)
{
   auto bop = [](auto a, auto b) { return a - b; };

   return MyExpr< MyExpr<LE, RE, Bop>, MyExpr<RawR, void, void>, decltype(bop) > { l, MyExpr<RawR, void, void>{r}, bop, " - " };
}

template<class LE, class RE, class Bop>
void foo(const char* str, MyExpr<LE, RE, Bop> expr)
{
   if(!expr.value())
   {
      std::cout << "Expression [" << str << "] failed [";
      expr.print();
      std::cout << "]\n";
   }
}

#define FOO(x) do { foo( #x, (Lifter() + x) ); } while(false)















































int main()
{
   int a = 15, b = 12;

   FOO(b < a);
   FOO(a < b);
   FOO(a + 1 < b);
   FOO(a == b);
}


