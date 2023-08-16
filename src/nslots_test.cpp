#include <stdio.h>
#include <iostream>
#include <sstream>

#include <helib/helib.h>

#include <fstream>

/*HELIB*/
using namespace helib;
using namespace std;
using namespace NTL;

int main() {
	vector<int> ms, ps, maxs;
	for (int m = 20000; m < 40000; ++m)
		if (phi_N(m) > 20000) ms.push_back(m);
	
	ps = {23, 29, 31, 41, 61, 71, 103, 131, 163, 173};
	maxs = {71, 30, 27, 50, 57, 38, 71, 46, 55, 68};
	auto it = maxs.begin();

	ofstream params;
	params.open("./params.txt", std::ios::out);
	double longmax = log(ULONG_MAX);
	int power, counter;
	float tick = (float)100/20;
	for (int& p: ps)
	{
		power = (int)(longmax / log((p+1)/2)) + 1;
		counter = 0;
		float percent;
		int bar_count;
		for (int& m: ms)
		{
			long ordp = multOrd(p, m);
			if (ordp < power || ordp > 40) continue;
			printf("\rp: %d					%d/%d [", p, counter, *it);
			percent = (float)counter/(*it) * 100;
			bar_count = percent/tick;
			for (int i = 0; i < 20; ++i)
			{
				if (bar_count > i) printf("=");
				else printf(" ");
			}
			printf("] %0.2f%%", percent);
			fflush(stdout);
			const Context c = ContextBuilder<BGV>().p(p)
												  .m(m)
												  .bits(500)
												  .c(3)
												  .r(1)
												  .build();
			counter++;
			if (c.securityLevel() < 128) continue;
			params << p << "," << m << "\n";
		}
		it++;
		cout << ", count: " << counter << endl;
	}
	params.close();

    return 0;
}



