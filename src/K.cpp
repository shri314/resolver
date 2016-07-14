#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iterator>
#include <experimental/optional>

namespace std {
using std::experimental::optional;
}

// #include <boost/algorithm/string/find.hpp>

struct tracker
{
std::map< std::string, int, std::less<> > m_name2offset;
int m_current_offset = 0;

template<class T>
std::optional<int> find_offset( T&& n ) const
{
    auto&& i = m_name2offset.find( std::forward<T>(n) );
    
    if(i != m_name2offset.end())
       return std::optional<int>(i->second);
    else
       return std::optional<int>{};
}

void increment_offset(int amount = 1) { m_current_offset += amount; }

template<class T>
void record_offset_of(T&& n) {
    m_name2offset.emplace( std::forward<T>(n), m_current_offset );
}

};


template<class Range, class Search>
std::pair<Range, Range> split2_at(const Range& input, const Search& s)
{
    auto&& begin = std::begin(input);
    auto&& end = std::end(input);
    
    auto&& pos = std::find( begin, end, s );
    
    return std::make_pair( Range(begin, pos), Range(pos != end ? std::next(pos) : end, end) );
}

template<class OutputIterator, class Range>
void zzz(OutputIterator& o, const Range& range, tracker& on_tr)
{
    auto&& emit = [&o, &on_tr](auto left, auto x, auto right)
    {
        if(left)
        { *o++ = left; }
        
        if(x == 3)
        {
           std::cout << x;
           *o++ = '3';
           std::cout << x;
        }
           
        *o++ = x;
        
        on_tr.increment_offset();

        if(right)
        { *o++ = right; }
    };
    
    if(!range.empty())
    {
       auto&& p_offset = on_tr.find_offset( range );
    
       if(p_offset)
       {
           emit( '<', *p_offset, '>' );
       }
       else
       {
           on_tr.record_offset_of( range );

           auto&& split_parts = split2_at(range, '.');
           
           // process split_parts.first
           auto&& sz = size( split_parts.first );
           
           emit('[', int(sz), ']');
           
           std::for_each( std::begin(split_parts.first), std::end(split_parts.first), [&emit](auto x) { emit(0, x, 0); } );
           
           zzz( o, split_parts.second, on_tr ); 
       }
    }
    else
    {
        std::cout << "0\n";
    }
}

int main()
{
    tracker no_tr{};
    no_tr.increment_offset();
    
    std::ostream_iterator<char> o(std::cout);
    
    zzz(o, std::string("www.yahoo.co.in"), no_tr);
    zzz(o, std::string("www.google.com"), no_tr);
    zzz(o, std::string("www.google.com"), no_tr);
    zzz(o, std::string("www.yahoo.com"), no_tr);
}
