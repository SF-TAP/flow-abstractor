#include "../src/fabs_slab.hpp"

#include <sys/time.h>
#include <unistd.h>

#include <thread>

volatile unsigned long long num = 0;

void
worker()
{
    fabs_slab<long long> slab;
    long long* ptr[64 * 64 * 2];

    for (;;) {
        for (int i = 0; i < 64 * 64 * 2; i++) {
            ptr[i] = slab.allocate();
            //ptr[i] = (long long*)malloc(sizeof(long long));
            __sync_fetch_and_add(&num, 1);
        }

        for (int i = 0; i < 64 * 64 * 2; i++) {
            slab.deallocate(ptr[i]);
            //free(ptr[i]);
            __sync_fetch_and_add(&num, 1);
        }

        //auto p = malloc(sizeof(long long));
        //free(p);
    }
}

void
timer()
{
    for (;;) {
        timeval t0, t1;
        unsigned long long num0 = num;
        gettimeofday(&t0, nullptr);

        sleep(10);

        gettimeofday(&t1, nullptr);
        unsigned long long num1 = num;

        double diff = (t1.tv_sec + t1.tv_usec * 1.0e-6) - (t0.tv_sec + t0.tv_usec * 1.0e-6);
        printf("%lf [ops/s]\n", (num1 - num0) / diff);
    }
}

int
main(int argc, char *argv[])
{
    for (int i = 0; i < std::thread::hardware_concurrency(); i++) {
        new std::thread(worker);
    }
    new std::thread(timer);

    sleep(1000);

    return 0;
}