#include "libtorrent/ip_filter.hpp"
#include <boost/utility.hpp>

#include "test.hpp"

using namespace libtorrent;

bool compare(ip_filter::ip_range const& lhs
	, ip_filter::ip_range const& rhs)
{
	return lhs.first == rhs.first
		&& lhs.last == rhs.last
		&& lhs.flags == rhs.flags;
}

void test_rules_invariant(std::vector<ip_filter::ip_range> const& r, ip_filter const& f)
{
	typedef std::vector<ip_filter::ip_range>::const_iterator iterator;
	TEST_CHECK(!r.empty());
	if (r.empty()) return;

	TEST_CHECK(r.front().first == address::from_string("0.0.0.0"));
	TEST_CHECK(r.back().last == address::from_string("255.255.255.255"));
	
	iterator i = r.begin();
	iterator j = boost::next(i);
	for (iterator i(r.begin()), j(boost::next(r.begin()))
		, end(r.end()); j != end; ++j, ++i)
	{
		TEST_CHECK(f.access(i->last) == i->flags);
		TEST_CHECK(f.access(j->first) == j->flags);
		TEST_CHECK(i->last.to_ulong() + 1 == j->first.to_ulong());
	}
}

int test_main()
{
	using namespace libtorrent;
	std::vector<ip_filter::ip_range> range;

	// **** test joining of ranges at the end ****
	ip_filter::ip_range expected1[] =
	{
		{address::from_string("0.0.0.0"), address::from_string("0.255.255.255"), 0}
		, {address::from_string("1.0.0.0"), address::from_string("3.0.0.0"), ip_filter::blocked}
		, {address::from_string("3.0.0.1"), address::from_string("255.255.255.255"), 0}
	};
	
	{
		ip_filter f;
		f.add_rule(address::from_string("1.0.0.0"), address::from_string("2.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("2.0.0.1"), address::from_string("3.0.0.0"), ip_filter::blocked);

		range = f.export_filter();
		test_rules_invariant(range, f);

		TEST_CHECK(range.size() == 3);
		TEST_CHECK(std::equal(range.begin(), range.end(), expected1, &compare));
	}
	
	// **** test joining of ranges at the start ****

	{
		ip_filter f;
		f.add_rule(address::from_string("2.0.0.1"), address::from_string("3.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("1.0.0.0"), address::from_string("2.0.0.0"), ip_filter::blocked);

		range = f.export_filter();
		test_rules_invariant(range, f);

		TEST_CHECK(range.size() == 3);
		TEST_CHECK(std::equal(range.begin(), range.end(), expected1, &compare));
	}	


	// **** test joining of overlapping ranges at the start ****

	{
		ip_filter f;
		f.add_rule(address::from_string("2.0.0.1"), address::from_string("3.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("1.0.0.0"), address::from_string("2.4.0.0"), ip_filter::blocked);

		range = f.export_filter();
		test_rules_invariant(range, f);

		TEST_CHECK(range.size() == 3);
		TEST_CHECK(std::equal(range.begin(), range.end(), expected1, &compare));
	}	


	// **** test joining of overlapping ranges at the end ****

	{
		ip_filter f;
		f.add_rule(address::from_string("1.0.0.0"), address::from_string("2.4.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("2.0.0.1"), address::from_string("3.0.0.0"), ip_filter::blocked);

		range = f.export_filter();
		test_rules_invariant(range, f);

		TEST_CHECK(range.size() == 3);
		TEST_CHECK(std::equal(range.begin(), range.end(), expected1, &compare));
	}	


	// **** test joining of multiple overlapping ranges 1 ****

	{
		ip_filter f;
		f.add_rule(address::from_string("1.0.0.0"), address::from_string("2.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("3.0.0.0"), address::from_string("4.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("5.0.0.0"), address::from_string("6.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("7.0.0.0"), address::from_string("8.0.0.0"), ip_filter::blocked);

		f.add_rule(address::from_string("1.0.1.0"), address::from_string("9.0.0.0"), ip_filter::blocked);
		
		range = f.export_filter();
		test_rules_invariant(range, f);

		TEST_CHECK(range.size() == 3);
		ip_filter::ip_range expected[] =
		{
			{address::from_string("0.0.0.0"), address::from_string("0.255.255.255"), 0}
			, {address::from_string("1.0.0.0"), address::from_string("9.0.0.0"), ip_filter::blocked}
			, {address::from_string("9.0.0.1"), address::from_string("255.255.255.255"), 0}
		};
	
		TEST_CHECK(std::equal(range.begin(), range.end(), expected, &compare));
	}	

	// **** test joining of multiple overlapping ranges 2 ****

	{
		ip_filter f;
		f.add_rule(address::from_string("1.0.0.0"), address::from_string("2.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("3.0.0.0"), address::from_string("4.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("5.0.0.0"), address::from_string("6.0.0.0"), ip_filter::blocked);
		f.add_rule(address::from_string("7.0.0.0"), address::from_string("8.0.0.0"), ip_filter::blocked);

		f.add_rule(address::from_string("0.0.1.0"), address::from_string("7.0.4.0"), ip_filter::blocked);
		
		range = f.export_filter();
		test_rules_invariant(range, f);

		TEST_CHECK(range.size() == 3);
		ip_filter::ip_range expected[] =
		{
			{address::from_string("0.0.0.0"), address::from_string("0.0.0.255"), 0}
			, {address::from_string("0.0.1.0"), address::from_string("8.0.0.0"), ip_filter::blocked}
			, {address::from_string("8.0.0.1"), address::from_string("255.255.255.255"), 0}
		};
	
		TEST_CHECK(std::equal(range.begin(), range.end(), expected, &compare));
	}	

	return 0;
}

