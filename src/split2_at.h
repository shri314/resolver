#pragma once

template<class Range, class Search>
std::pair<Range, Range> split2_at(const Range& input, const Search& s)
{
   auto&& begin = std::begin(input);
   auto&& end = std::end(input);

   auto&& pos = std::find(begin, end, s);

   return std::make_pair(Range(begin, pos), Range(pos != end ? std::next(pos) : end, end));
}


